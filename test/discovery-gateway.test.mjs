import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createServer, request as httpRequest } from "node:http";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { randomUUID } from "node:crypto";

const root = resolve(import.meta.dirname, "..");
let policy;
let gatewayModule;
test("discovery gateway denies forbidden address classes and mapped IPv4", async () => {
  const module = await import(pathToFileURL(resolve(root, "apps/api/dist/discovery-gateway.js")));
  for (const address of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1"]) {
    assert.equal(module.isDisallowedAddress(address), true, address);
  }
  assert.equal(module.isDisallowedAddress("8.8.8.8"), false);
  assert.equal(module.isDisallowedAddress("2606:4700:4700::1111"), false);
});

test("gateway enforces path boundary, ignores redirects, strips sensitive headers and rejects mixed DNS", async (t) => {
  const scopePolicy = await import(pathToFileURL(resolve(root, "apps/api/dist/discovery-scope-policy.js")));
  const contracts = await import(pathToFileURL(resolve(root, "apps/api/dist/discovery-contracts.js")));
  gatewayModule = await import(pathToFileURL(resolve(root, "apps/api/dist/discovery-gateway.js")));
  policy = { scopePolicy, contracts };
  const work = await mkdtemp(join(tmpdir(), "sapphire-gateway-"));
  t.after(() => rm(work, { recursive: true, force: true }));
  for (const dir of ["requests", "scopes", "budgets", "cancel"]) await mkdir(join(work, dir));
  const seen = [];
  const target = createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, cookie: req.headers.cookie, authorization: req.headers.authorization });
    if (req.url === "/prefix/redirect") { res.writeHead(302, { location: "http://other.test:1/outside" }); res.end("redirect"); return; }
    res.writeHead(200, { "content-type": "text/plain" }); res.end("ok");
  });
  target.listen(0, "127.0.0.1"); await once(target, "listening");
  t.after(() => target.close());
  const port = target.address().port;
  const scopeId = randomUUID(); const runId = randomUUID(); const assessmentId = randomUUID();
  const scope = scopePolicy.createDiscoveryScope({ scope_id: scopeId, assessment_id: assessmentId, origin: `http://example.test:${port}`, path_mode: "prefix", path_prefixes: ["/prefix"], pinned_ips: ["127.0.0.1"], policy_revision: "test-v1", authorization_actor: "test-operator", authorized_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 60000).toISOString() });
  const task = { schema_version: 1, assessment_id: assessmentId, tool_run_id: runId, scope_id: scopeId, scope_policy_sha256: scope.policy_sha256, tool: "httpx", seed_url: `http://example.test:${port}/prefix`, budget_profile_id: "test-profile", cancellation_ref: runId };
  const budget = { ...contracts.DEFAULT_DISCOVERY_BUDGET, profile_id: "test-profile", max_response_bytes: 2048, total_response_bytes: 4096 };
  await writeFile(join(work, "requests", `${runId}.json`), JSON.stringify(task));
  await writeFile(join(work, "scopes", `${scopeId}.json`), JSON.stringify(scope));
  await writeFile(join(work, "budgets", "test-profile.json"), JSON.stringify(budget));
  const proxy = gatewayModule.createDiscoveryGateway({ workDir: work, localTargets: [`example.test:127.0.0.1:${port}`], resolveAll: async () => ["127.0.0.1"] });
  proxy.server.listen(0, "127.0.0.1"); await once(proxy.server, "listening");
  t.after(() => proxy.close());
  const proxyPort = proxy.server.address().port;
  const auth = `Basic ${Buffer.from(`${runId}:${scope.policy_sha256}`).toString("base64")}`;
  const send = (path, extraHeaders = {}) => new Promise((resolveRequest, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port: proxyPort, method: "GET", path: `http://example.test:${port}${path}`, headers: { "proxy-authorization": auth, cookie: "session=private", authorization: "Bearer private", ...extraHeaders } }, (res) => {
      const chunks = []; res.on("data", (chunk) => chunks.push(chunk)); res.on("end", () => resolveRequest({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject); req.end();
  });
  const ok = await send("/prefix/child");
  assert.equal(ok.status, 200, JSON.stringify(ok.headers));
  assert.deepEqual(seen[0], { method: "GET", url: "/prefix/child", cookie: undefined, authorization: undefined });
  const denied = await send("/prefix-escape");
  assert.equal(denied.status, 403);
  assert.equal(denied.headers["x-discovery-policy-reason"], "scope_path_denied");
  assert.equal(seen.length, 1, "out-of-scope path never reaches target");
  await delay(1100);
  const redirect = await send("/prefix/redirect");
  assert.equal(redirect.status, 302, JSON.stringify(redirect.headers));
  assert.equal(redirect.headers["x-discovery-policy-reason"], "redirect_denied");
  assert.equal(redirect.headers.location, undefined, "redirect destination is not exposed/followed");
  assert.equal(seen.length, 2, "redirect target is not requested");
  const mixed = gatewayModule.createDiscoveryGateway({ workDir: work, localTargets: [`example.test:127.0.0.1:${port}`], resolveAll: async () => ["127.0.0.1", "8.8.8.8"] });
  mixed.server.listen(0, "127.0.0.1"); await once(mixed.server, "listening");
  const mixedPort = mixed.server.address().port;
  const mixedResult = await new Promise((resolveRequest, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port: mixedPort, path: `http://example.test:${port}/prefix/child`, headers: { "proxy-authorization": auth } }, (res) => { res.resume(); res.on("end", () => resolveRequest(res)); });
    req.on("error", reject); req.end();
  });
  assert.equal(mixedResult.statusCode, 403);
  assert.equal(mixedResult.headers["x-discovery-policy-reason"], "dns_policy_rejected");
  await delay(100);
  const eventText = await readFile(join(work, "gateway-events", `${runId}.jsonl`), "utf8");
  const events = eventText.trim().split("\n").map((line) => JSON.parse(line));
  assert.ok(events.some((event) => event.reason_code === "scope_path_denied"));
  assert.ok(events.some((event) => event.reason_code === "redirect_denied"));
  assert.ok(events.some((event) => event.reason_code === "dns_policy_rejected"));
  for (const event of events) {
    assert.deepEqual(Object.keys(event).sort(), ["reason_code", "timestamp"]);
    assert.equal(typeof event.timestamp, "string");
    assert.equal(typeof event.reason_code, "string");
  }
  await mixed.close();
});

test("proxy credential binding fails closed for wrong run/hash and cancelled runs", async (t) => {
  if (!policy) {
    policy = { scopePolicy: await import(pathToFileURL(resolve(root, "apps/api/dist/discovery-scope-policy.js"))), contracts: await import(pathToFileURL(resolve(root, "apps/api/dist/discovery-contracts.js"))) };
    gatewayModule = await import(pathToFileURL(resolve(root, "apps/api/dist/discovery-gateway.js")));
  }
  const work = await mkdtemp(join(tmpdir(), "sapphire-gateway-cancel-"));
  t.after(() => rm(work, { recursive: true, force: true }));
  for (const dir of ["requests", "scopes", "budgets", "cancel"]) await mkdir(join(work, dir));
  const scopeId = randomUUID(); const runId = randomUUID(); const assessmentId = randomUUID();
  const scope = policy.scopePolicy.createDiscoveryScope({ scope_id: scopeId, assessment_id: assessmentId, origin: "http://example.test:80", path_mode: "whole_origin", pinned_ips: ["8.8.8.8"], policy_revision: "test-v1", authorization_actor: "test", authorized_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 60000).toISOString() });
  const task = { schema_version: 1, assessment_id: assessmentId, tool_run_id: runId, scope_id: scopeId, scope_policy_sha256: scope.policy_sha256, tool: "httpx", seed_url: "http://example.test/", budget_profile_id: "test", cancellation_ref: runId };
  await writeFile(join(work, "requests", `${runId}.json`), JSON.stringify(task));
  await writeFile(join(work, "scopes", `${scopeId}.json`), JSON.stringify(scope));
  await writeFile(join(work, "budgets", "test.json"), JSON.stringify({ ...policy.contracts.DEFAULT_DISCOVERY_BUDGET, profile_id: "test" }));
  const proxy = gatewayModule.createDiscoveryGateway({ workDir: work, resolveAll: async () => ["8.8.8.8"] });
  proxy.server.listen(0, "127.0.0.1"); await once(proxy.server, "listening"); t.after(() => proxy.close());
  const port = proxy.server.address().port;
  const send = (credential) => new Promise((resolveRequest, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: "http://example.test/", headers: { "proxy-authorization": `Basic ${Buffer.from(credential).toString("base64")}` } }, (res) => { res.resume(); res.on("end", () => resolveRequest(res)); }); req.on("error", reject); req.end();
  });
  assert.equal((await send(`${runId}:${"0".repeat(64)}`)).headers["x-discovery-policy-reason"], "scope_invalid");
  await writeFile(join(work, "cancel", runId), "cancel");
  assert.equal((await send(`${runId}:${scope.policy_sha256}`)).headers["x-discovery-policy-reason"], "cancelled");
  await delay(100);
  const eventFile = join(work, "gateway-events", `${runId}.jsonl`);
  const fullEvents = Array.from({ length: 256 }, (_, i) => JSON.stringify({ timestamp: new Date().toISOString(), reason_code: i === 0 ? "cancelled" : "scope_invalid" })).join("\n") + "\n";
  await writeFile(eventFile, fullEvents);
  assert.equal((await send(`${runId}:${scope.policy_sha256}`)).headers["x-discovery-policy-reason"], "cancelled");
  await delay(100);
  const eventText = await readFile(eventFile, "utf8");
  const events = eventText.trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(events.length, 256);
  assert.ok(Buffer.byteLength(eventText) <= 64 * 1024);
  assert.ok(events.some((event) => event.reason_code === "cancelled"));
  assert.ok(events.every((event) => ["cancelled", "scope_invalid"].includes(event.reason_code) && Object.keys(event).length === 2));
});
