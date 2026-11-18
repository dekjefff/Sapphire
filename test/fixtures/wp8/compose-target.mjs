import { appendFile } from "node:fs/promises";
import { createServer } from "node:http";

const logPath = process.env.REQUEST_LOG ?? "/logs/requests.jsonl";

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://discovery-test-target:3000");
  await appendFile(logPath, `${JSON.stringify({ method: request.method ?? "", path: url.pathname })}\n`, { mode: 0o600 });
  if (request.method !== "GET") {
    response.writeHead(405, { allow: "GET", "content-type": "text/plain" });
    response.end("GET only");
    return;
  }
  if (url.pathname === "/") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end('<!doctype html><a href="/vulnerable">vulnerable</a><a href="/items/42">item</a>');
    return;
  }
  if (url.pathname === "/vulnerable") {
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end("harmless marker; query input is never evaluated");
    return;
  }
  if (/^\/items\/[^/]+$/.test(url.pathname)) {
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end("dynamic item marker");
    return;
  }
  response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  response.end("not found");
});

server.listen(3000, "0.0.0.0");
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => server.close(() => process.exit(0)));
