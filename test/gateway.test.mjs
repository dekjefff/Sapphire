import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const live = new Set();
let gatewayApi;
let scopeApi;
let contractApi;
try {
  const gatewayPath = resolve(root, "apps/api/dist/discovery-gateway.js");
  const scopePath = resolve(root, "apps/api/dist/discovery-scope-policy.js");
  const contractPath = resolve(root, "apps/api/dist/discovery-contracts.js");
  await Promise.all([access(gatewayPath), access(scopePath), access(contractPath)]);
  [gatewayApi, scopeApi, contractApi] = await Promise.all([gatewayPath, scopePath, contractPath].map(path => import(pathToFileURL(path))));
} catch { /* tests record an explicit skip below */ }

function basic(runId, hash) { return `Basic ${Buffer.from(`${runId}:${hash}`).toString("base64")}`; }

test("Katana proxy bootstrap is answered locally only for the exact fixed probe", t => {
  if (!gatewayApi) return t.skip("API dist modules unavailable; run npm --prefix apps/api run build");
  assert.equal(gatewayApi.isKatanaProxyProbe("katana", "GET", "http://burpsuite/"), true);
  for (const candidate of [
    ["httpx", "GET", "http://burpsuite/"], ["katana", "POST", "http://burpsuite/"],
    ["katana", "GET", "http://burpsuite/path"], ["katana", "GET", "https://burpsuite/"],
  ]) assert.equal(gatewayApi.isKatanaProxyProbe(...candidate), false);
});

async function listen(server) {
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return server.address().port;
}

async function makeTarget({ slowMs = 150, largeBytes = 128 * 1024 } = {}) {
  const seen = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://target.invalid");
    seen.push({ method: req.method, path: url.pathname, headers: req.headers });
    if (url.pathname === "/redirect") { res.writeHead(302, { location: "/outside-prefix" }); res.end("redirect"); return; }
    if (url.pathname === "/slow") { setTimeout(() => { res.writeHead(200); res.end("slow response"); }, slowMs); return; }
    if (url.pathname === "/oversized") { res.writeHead(200, { "content-length": String(largeBytes) }); res.end("x".repeat(largeBytes)); return; }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ path: url.pathname, method: req.method, headers: req.headers }));
  });
  const port = await listen(server);
  live.add(() => new Promise(resolve => server.close(resolve)));
  return { server, seen, port };
}

async function prepare({ host = "app.local", target = null, mode = "prefix", prefixes = ["/api"], ips = null, resolver = null, localTargets = null, budgetPatch = {}, now = () => new Date() } = {}) {
  const workDir = await import("node:fs/promises").then(fs => fs.mkdtemp(join(tmpdir(), "sapphire-gateway-")));
  live.add(() => rm(workDir, { recursive: true, force: true }));
  const upstream = target ?? await makeTarget();
  const scopeId = randomUUID(); const assessmentId = randomUUID(); const runId = randomUUID();
  const pinned = ips ?? ["127.0.0.1"];
  const port = upstream.port;
  const origin = `${mode === "whole" ? "https" : "http"}://${host}:${port}`;
  const scope = scopeApi.createDiscoveryScope({
    scope_id: scopeId, assessment_id: assessmentId, origin, path_mode: mode === "whole" ? "whole_origin" : mode,
    path_prefixes: mode === "whole" ? [] : prefixes, pinned_ips: pinned, policy_revision: "gateway-test-v1",
    authorization_actor: "isolated gateway tests", authorized_at: new Date(Date.now() - 1000).toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  const profile = { ...contractApi.DEFAULT_DISCOVERY_BUDGET, profile_id: "gateway-test", ...budgetPatch };
  const task = { schema_version: 1, assessment_id: assessmentId, tool_run_id: runId, scope_id: scopeId, scope_policy_sha256: scope.policy_sha256,
    tool: "httpx", seed_url: `${origin}/`, budget_profile_id: profile.profile_id, cancellation_ref: runId };
  for (const name of ["requests", "scopes", "budgets", "cancel", "gateway-events"]) await mkdir(join(workDir, name), { recursive: true });
  await Promise.all([
    writeFile(join(workDir, "requests", `${runId}.json`), JSON.stringify(task)),
    writeFile(join(workDir, "scopes", `${scopeId}.json`), JSON.stringify(scope)),
    writeFile(join(workDir, "budgets", `${profile.profile_id}.json`), JSON.stringify(profile)),
  ]);
  const targets = localTargets ?? [`${host}:127.0.0.1:${port}`];
  const gateway = gatewayApi.createDiscoveryGateway({ workDir, localTargets: targets, resolveAll: resolver ?? (async () => pinned), now });
  const gatewayPort = await listen(gateway.server);
  live.add(() => gateway.close());
  return { workDir, upstream, scope, profile, task, runId, gateway, gatewayPort, origin, authorization: basic(runId, scope.policy_sha256) };
}

async function proxyRequest(ctx, { url = `${ctx.origin}/api`, method = "GET", headers = {}, auth = ctx.authorization } = {}) {
  return new Promise((resolve, reject) => {
    const req = (awaitImportHttp()).request({ host: "127.0.0.1", port: ctx.gatewayPort, path: url, method, headers: { ...headers, ...(auth ? { "proxy-authorization": auth } : {}) }, agent: false }, res => {
      const chunks = [];
      res.on("data", chunk => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      res.on("aborted", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), aborted: true }));
    });
    req.setTimeout(4000, () => req.destroy(new Error("test proxy request timed out")));
    req.on("error", error => error.code === "ECONNRESET" ? resolve({ aborted: true, body: "" }) : reject(error));
    req.end();
  });
}

// Avoid a top-level import solely for one helper in the request path.
function awaitImportHttp() { return httpModule; }
import * as httpModule from "node:http";

async function connectRequest(ctx, authority, auth = ctx.authorization) {
  return new Promise((resolve, reject) => {
    const socket = awaitImportNet().connect(ctx.gatewayPort, "127.0.0.1");
    let data = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error("test CONNECT timed out")); }, 3000);
    socket.on("connect", () => socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${auth ? `Proxy-Authorization: ${auth}\r\n` : ""}\r\n`));
    socket.on("data", chunk => {
      data = Buffer.concat([data, chunk]);
      if (data.includes(Buffer.from("\r\n\r\n"))) { clearTimeout(timer); socket.destroy(); resolve(data.toString("latin1").split("\r\n")[0]); }
    });
    socket.on("error", error => { clearTimeout(timer); reject(error); });
  });
}
import * as netModule from "node:net";
function awaitImportNet() { return netModule; }

test("WP4 proxy authentication, task identity and exact local target allow", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const ctx = await prepare();
  const missing = await proxyRequest(ctx, { auth: null });
  assert.equal(missing.status, 403);
  const wrongHash = await proxyRequest(ctx, { auth: basic(ctx.runId, "b".repeat(64)) });
  assert.equal(wrongHash.headers["x-discovery-policy-reason"], "scope_invalid");
  const ok = await proxyRequest(ctx);
  assert.equal(ok.status, 200);
  assert.equal(ctx.upstream.seen.length, 1);
});

test("WP4 rejects mismatched queued task, scope hash, budget and expired scope", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const taskMismatch = await prepare();
  const taskFile = join(taskMismatch.workDir, "requests", `${taskMismatch.runId}.json`);
  const alteredTask = { ...taskMismatch.task, tool_run_id: randomUUID() };
  await writeFile(taskFile, JSON.stringify(alteredTask));
  assert.equal((await proxyRequest(taskMismatch)).headers["x-discovery-policy-reason"], "scope_invalid");

  const scopeMismatch = await prepare();
  await writeFile(join(scopeMismatch.workDir, "requests", `${scopeMismatch.runId}.json`), JSON.stringify({ ...scopeMismatch.task, scope_id: randomUUID() }));
  assert.equal((await proxyRequest(scopeMismatch)).headers["x-discovery-policy-reason"], "scope_invalid");

  const budgetMismatch = await prepare();
  const badBudget = { ...budgetMismatch.profile, unique_urls: 501 };
  await writeFile(join(budgetMismatch.workDir, "budgets", `${badBudget.profile_id}.json`), JSON.stringify(badBudget));
  assert.equal((await proxyRequest(budgetMismatch)).headers["x-discovery-policy-reason"], "scope_invalid");

  const expired = await prepare();
  const expiredScope = scopeApi.createDiscoveryScope({
    scope_id: expired.scope.scope_id, assessment_id: expired.scope.assessment_id,
    origin: expired.origin, path_mode: "prefix", path_prefixes: ["/api"], pinned_ips: ["127.0.0.1"],
    policy_revision: "expired-test", authorization_actor: "isolated gateway tests",
    authorized_at: "2020-01-01T00:00:00.000Z", expires_at: "2020-01-02T00:00:00.000Z",
  });
  await writeFile(join(expired.workDir, "scopes", `${expired.scope.scope_id}.json`), JSON.stringify(expiredScope));
  await writeFile(join(expired.workDir, "requests", `${expired.runId}.json`), JSON.stringify({ ...expired.task, scope_policy_sha256: expiredScope.policy_sha256 }));
  expired.authorization = basic(expired.runId, expiredScope.policy_sha256);
  assert.equal((await proxyRequest(expired)).headers["x-discovery-policy-reason"], "scope_expired");
});

test("WP4 enforces HTTP GET and segment path prefix before forwarding", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const ctx = await prepare();
  const pathDenied = await proxyRequest(ctx, { url: `${ctx.origin}/apix` });
  assert.equal(pathDenied.headers["x-discovery-policy-reason"], "scope_path_denied");
  const methodDenied = await proxyRequest(ctx, { method: "POST", headers: { "content-type": "text/plain" } });
  assert.equal(methodDenied.headers["x-discovery-policy-reason"], "scope_origin_denied");
  assert.equal(ctx.upstream.seen.length, 0);
});

test("WP4 strips proxy/auth/cookie/connection headers and does not follow redirects", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const ctx = await prepare({ prefixes: ["/"] });
  const response = await proxyRequest(ctx, { headers: { authorization: "Bearer TEST_AUTH", cookie: "sid=TEST_COOKIE", "x-hop": "TEST_HOP", connection: "x-hop" } });
  const echoed = JSON.parse(response.body);
  for (const blocked of ["proxy-authorization", "authorization", "cookie", "x-hop"]) assert.equal(echoed.headers[blocked], undefined);
  const redirectCtx = await prepare({ prefixes: ["/"] });
  const redirect = await proxyRequest(redirectCtx, { url: `${redirectCtx.origin}/redirect` });
  assert.equal(redirect.status, 302);
  assert.equal(redirect.headers["x-discovery-policy-reason"], "redirect_denied");
  assert.equal(redirect.headers.location, undefined);
  assert.equal(redirectCtx.upstream.seen.filter(row => row.path === "/outside-prefix").length, 0);
});

test("WP4 denies mixed/private DNS and allows only the exact configured local-test triple", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const denied = await prepare({ localTargets: [] });
  const deniedResponse = await proxyRequest(denied);
  assert.equal(deniedResponse.headers["x-discovery-policy-reason"], "dns_policy_rejected");
  const mixed = await prepare({ host: "mixed.local", ips: ["127.0.0.1", "198.51.100.8"], resolver: async () => ["127.0.0.1", "198.51.100.8"], localTargets: ["mixed.local:127.0.0.1:1"] });
  const mixedResponse = await proxyRequest(mixed);
  assert.equal(mixedResponse.headers["x-discovery-policy-reason"], "dns_policy_rejected");
  const local = await prepare({ localTargets: ["app.local:127.0.0.1:1"] });
  const localResponse = await proxyRequest(local);
  assert.equal(localResponse.headers["x-discovery-policy-reason"], "dns_policy_rejected");
});

test("WP4 CONNECT rejects path-scoped HTTPS and wrong origin", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const tcp = createTcpServer(socket => socket.on("data", chunk => socket.write(chunk)));
  const port = await new Promise((resolve, reject) => { tcp.once("error", reject); tcp.listen(0, "127.0.0.1", () => resolve(tcp.address().port)); });
  live.add(() => new Promise(resolve => tcp.close(resolve)));
  const prefixed = await prepare({ host: "app.local", mode: "prefix", prefixes: ["/api"], target: { port } });
  const prefixStatus = await connectRequest(prefixed, `app.local:${port}`);
  assert.match(prefixStatus, /403 Forbidden/);
  const whole = await prepare({ host: "app.local", mode: "whole", target: { port } });
  const wrongHost = await connectRequest(whole, `other.local:${port}`);
  assert.match(wrongHost, /403 Forbidden/);
  const allowed = await connectRequest(await prepare({ host: "app.local", mode: "whole", target: { port } }), `app.local:${port}`);
  assert.match(allowed, /200 Connection Established/);
});

test("WP4 side-channel records bounded safe denial objects", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const ctx = await prepare();
  for (let i = 0; i < 260; i++) await proxyRequest(ctx, { url: `${ctx.origin}/denied-${i}` });
  const file = join(ctx.workDir, "gateway-events", `${ctx.runId}.jsonl`);
  for (let i = 0; i < 20; i++) {
    try { await access(file); break; } catch { await new Promise(resolve => setTimeout(resolve, 20)); }
  }
  const raw = await readFile(file, "utf8");
  const lines = raw.trim().split("\n");
  assert.ok(lines.length <= 256);
  assert.ok(Buffer.byteLength(raw) <= 64 * 1024);
  for (const line of lines) {
    const event = JSON.parse(line);
    assert.deepEqual(Object.keys(event).sort(), ["reason_code", "timestamp"]);
    assert.equal(event.reason_code, "scope_path_denied");
    assert.ok(!line.includes("denied-") && !line.includes(ctx.origin));
  }
});

test("WP4 rate scheduling and URL, byte, time and cancellation denials remain explicit", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  const rate = await prepare();
  const first = await proxyRequest(rate);
  assert.equal(first.status, 200);
  const rateStarted = Date.now();
  const second = await proxyRequest(rate, { url: `${rate.origin}/api/second` });
  assert.equal(second.status, 200);
  assert.ok(Date.now() - rateStarted >= 850, "second request must wait for its reserved rate slot");

  const rateExhausted = await prepare({ budgetPatch: { wall_clock_seconds: 2, requests_per_second: 0.25, per_host_requests_per_second: 0.25 } });
  assert.equal((await proxyRequest(rateExhausted)).status, 200);
  const noSlot = await proxyRequest(rateExhausted, { url: `${rateExhausted.origin}/api/second` });
  assert.equal(noSlot.headers["x-discovery-policy-reason"], "rate_budget_exhausted");

  let clock = Date.now();
  const url = await prepare({ budgetPatch: { unique_urls: 1 }, now: () => new Date(clock += 1100) });
  assert.equal((await proxyRequest(url)).status, 200);
  const overUrl = await proxyRequest(url, { url: `${url.origin}/api/second` });
  assert.equal(overUrl.headers["x-discovery-policy-reason"], "url_budget_exhausted");

  const bytes = await prepare({ prefixes: ["/"], budgetPatch: { max_response_bytes: 32 } });
  const tooLarge = await proxyRequest(bytes, { url: `${bytes.origin}/oversized` });
  assert.ok(tooLarge.aborted || tooLarge.body.length <= 32);

  const expiredClock = { value: Date.now() };
  const timed = await prepare({ budgetPatch: { wall_clock_seconds: 1 }, now: () => new Date(expiredClock.value += 10) });
  assert.equal((await proxyRequest(timed)).status, 200);
  expiredClock.value += 1500;
  const timeDenied = await proxyRequest(timed, { url: `${timed.origin}/api/second` });
  assert.equal(timeDenied.headers["x-discovery-policy-reason"], "timeout");

  const cancelled = await prepare();
  await writeFile(join(cancelled.workDir, "cancel", cancelled.runId), "");
  const cancelResponse = await proxyRequest(cancelled);
  assert.equal(cancelResponse.headers["x-discovery-policy-reason"], "cancelled");
});

test("WP4 concurrent request limit rejects a second in-flight request", async t => {
  if (!gatewayApi) return t.skip("Gateway dist module unavailable; run npm --prefix apps/api run build");
  let clock = Date.now();
  const ctx = await prepare({ prefixes: ["/"], now: () => new Date(clock += 1100) });
  const firstPromise = proxyRequest(ctx, { url: `${ctx.origin}/slow` });
  await new Promise(resolve => setTimeout(resolve, 40));
  const second = await proxyRequest(ctx, { url: `${ctx.origin}/api/second` });
  assert.equal(second.headers["x-discovery-policy-reason"], "concurrency_budget_exhausted");
  await firstPromise;
});

test.after(async () => { for (const close of [...live].reverse()) await close().catch(() => undefined); });
