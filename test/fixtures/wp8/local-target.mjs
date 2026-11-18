import { createServer } from "node:http";

/** Start an inert discovery target bound only to IPv4 loopback. */
export async function startLocalTarget({ peerOrigin = null, slowMs = 250, largeBytes = 2 * 1024 * 1024 } = {}) {
  const ledger = [];
  let rateLimitHits = 0;
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    ledger.push({ method: request.method ?? "", path: url.pathname, host: request.headers.host ?? "" });
    const send = (status, body, headers = {}) => {
      response.writeHead(status, { "content-type": "text/plain; charset=utf-8", ...headers });
      response.end(body);
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      // Deliberately records state-changing attempts without mutating application state.
      send(405, "method recorded; no state changed", { allow: "GET, HEAD" });
      return;
    }
    switch (url.pathname) {
      case "/": return send(200, "local discovery fixture");
      case "/in-scope": return send(200, "in-scope marker");
      case "/prefix/child": return send(200, "path prefix child");
      case "/redirect/path": return send(302, "", { location: "/outside-prefix" });
      case "/redirect/host": return send(302, "", { location: peerOrigin ? `${peerOrigin}/peer-only` : "http://127.0.0.1:1/peer-only" });
      case "/redirect/loop-a": return send(302, "", { location: "/redirect/loop-b" });
      case "/redirect/loop-b": return send(302, "", { location: "/redirect/loop-a" });
      case "/slow": return setTimeout(() => send(200, "slow marker"), slowMs);
      case "/oversized": return send(200, "x".repeat(largeBytes), { "content-length": String(largeBytes) });
      case "/rate-limit": rateLimitHits += 1; return send(rateLimitHits === 1 ? 429 : 200, "rate limit marker", { "retry-after": "0" });
      case "/server-error": return send(503, "server error marker");
      case "/vulnerable": return send(200, "harmless marker; query ignored");
      default: {
        if (url.pathname.startsWith("/items/") && url.pathname.split("/").length === 3) return send(200, "dynamic item marker");
        return send(404, "not found");
      }
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return {
    origin: `http://127.0.0.1:${address.port}`,
    ledger,
    async close() { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); },
  };
}
