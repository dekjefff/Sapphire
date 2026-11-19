import test, { before } from "node:test";
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
let adapters;
let parsers;
let contracts;
let scopeApi;
let fixtureHttpx;
let fixtureKatana;

before(async () => {
  const base = resolve(root, "apps/api/dist/discovery");
  const contractPath = resolve(root, "apps/api/dist/discovery-contracts.js");
  const scopePath = resolve(root, "apps/api/dist/discovery-scope-policy.js");
  try {
    await Promise.all([access(resolve(base, "adapters.js")), access(resolve(base, "parsers.js")), access(contractPath), access(scopePath)]);
    [adapters, parsers, contracts, scopeApi] = await Promise.all([
      import(pathToFileURL(resolve(base, "adapters.js"))),
      import(pathToFileURL(resolve(base, "parsers.js"))),
      import(pathToFileURL(contractPath)),
      import(pathToFileURL(scopePath)),
    ]);
    fixtureHttpx = await readFile(resolve(root, "apps/api/test/fixtures/httpx.jsonl"), "utf8");
    fixtureKatana = await readFile(resolve(root, "apps/api/test/fixtures/katana.jsonl"), "utf8");
  } catch { /* individual checks report a clear skip if the build is unavailable */ }
});

const runId = "33333333-3333-4333-8333-333333333333";
const assessmentId = "22222222-2222-4222-8222-222222222222";
const scopeId = "11111111-1111-4111-8111-111111111111";
const policyHash = "a".repeat(64);
const task = (tool = "httpx", overrides = {}) => ({
  schema_version: 1, assessment_id: assessmentId, tool_run_id: runId, scope_id: scopeId,
  scope_policy_sha256: policyHash, tool, seed_url: "http://app.local:3000/", budget_profile_id: "test-budget",
  cancellation_ref: runId, ...overrides,
});
const budget = () => ({ ...contracts.DEFAULT_DISCOVERY_BUDGET, profile_id: "test-budget" });
const approval = () => ({ scope_id: scopeId, assessment_id: assessmentId, origin: "http://app.local:3000", path_mode: "whole_origin", pinned_ips: ["192.0.2.10"], policy_revision: "wp3-test", authorization_actor: "WP3 tests", authorized_at: "2026-01-01T00:00:00.000Z", expires_at: "2030-01-01T00:00:00.000Z" });

function available(t) {
  if (!adapters || !parsers || !contracts || !scopeApi) {
    t.skip("API dist modules unavailable; run npm --prefix apps/api run build");
    return false;
  }
  return true;
}

test("WP3 adapters pin tool versions and derive proxy credentials from typed task", t => {
  if (!available(t)) return;
  assert.equal(adapters.HTTPX_VERSION, "1.12.0");
  assert.equal(adapters.KATANA_VERSION, "1.8.0");
  assert.equal(adapters.buildPolicyProxyUrl(task()), `http://${runId}:${policyHash}@discovery-gateway:8080`);
  assert.throws(() => adapters.buildPolicyProxyUrl(task("httpx", { tool_run_id: "bad" })));
  assert.throws(() => adapters.buildHttpxArgv(task("katana"), budget()));
  assert.throws(() => adapters.buildKatanaArgv(task("httpx"), scopeApi.createDiscoveryScope(approval()), budget()));
});

test("WP3 fixed argv is passive GET-only and excludes unsafe capabilities", t => {
  if (!available(t)) return;
  const scope = scopeApi.createDiscoveryScope(approval());
  const httpx = adapters.buildHttpxArgv(task("httpx"), budget());
  const katana = adapters.buildKatanaArgv(task("katana"), scope, budget());
  assert.ok(httpx.includes("GET"));
  assert.ok(katana.includes("-disable-redirects"));
  for (const argv of [httpx, katana]) {
    const flags = argv.filter(value => value.startsWith("-"));
    assert.ok(!flags.some(flag => /headless|javascript|js-crawl|form|auth|cookie|follow-redirect/i.test(flag)), flags.join(" "));
    assert.ok(argv.includes("-proxy"));
    assert.ok(!argv.some(value => value.includes("-H") || value.includes("--header")));
  }
  assert.ok(!httpx.includes("-follow-redirects"));
  assert.ok(!katana.includes("-headless"));
  assert.ok(!katana.includes("-js-crawl"));
});

test("WP3 JSONL fixtures discard queries, bodies, raw requests, cookies, auth and outside-scope URLs", t => {
  if (!available(t)) return;
  const scope = scopeApi.createDiscoveryScope(approval());
  const httpxRows = parsers.parseHttpxJsonl(fixtureHttpx, scope);
  const katanaRows = parsers.parseKatanaJsonl(fixtureKatana, scope);
  assert.equal(httpxRows.length, 2);
  assert.equal(katanaRows.length, 1);
  assert.equal(httpxRows[0].url, "http://app.local:3000/health");
  assert.equal(katanaRows[0].url, "http://app.local:3000/api/users");
  const safeJson = JSON.stringify([...httpxRows, ...katanaRows]);
  for (const secret of ["FIXTURE_SECRET_QUERY_SHOULD_NOT_PERSIST", "outside.example", "cookie", "authorization", "raw_request", "body"]) {
    assert.ok(!safeJson.toLowerCase().includes(secret.toLowerCase()), `sanitized output retained ${secret}`);
  }
  assert.ok(httpxRows[1].redirect_observed);
});

test("WP3 parsers discard wrong-scope observations and reject malformed or oversized output", t => {
  if (!available(t)) return;
  const scope = scopeApi.createDiscoveryScope(approval());
  assert.deepEqual(parsers.parseHttpxJsonl(JSON.stringify({ url: "http://elsewhere.test/secret" }), scope), []);
  assert.throws(() => parsers.parseHttpxJsonl("{bad json}", scope), parsers.DiscoveryParseError);
  assert.throws(() => parsers.parseKatanaJsonl(`${JSON.stringify({ url: "http://app.local:3000/" })}\n${"x".repeat(65 * 1024)}`, scope), parsers.DiscoveryParseError);
  assert.throws(() => parsers.parseHttpxJsonl(" ".repeat(8 * 1024 * 1024 + 1), scope), parsers.DiscoveryParseError);
  assert.equal(contracts.DiscoveryTaskSchema.safeParse({ ...task(), unexpected: "arbitrary flag" }).success, false);
  assert.equal(contracts.DiscoveryTaskSchema.safeParse({ ...task(), tool: "nmap" }).success, false);
});

test("WP3 runner source guards queue paths and binds cancellation to the task ID", async () => {
  const source = await readFile(resolve(root, "apps/api/src/discovery/runner.ts"), "utf8");
  assert.match(source, /const ROOT = "\/discovery-work"/);
  assert.match(source, /if \(!uuid\(base\)\) \{ await rm\(requestFile, \{ force: true \}\); return; \}/);
  assert.match(source, /task\.tool_run_id !== base/);
  assert.match(source, /task\.cancellation_ref !== task\.tool_run_id/);
  assert.match(source, /path\.join\(ROOT, "cancel", task\.tool_run_id\)/);
  assert.match(source, /fileExists\(cancelFile\)/);
  // This is a source guard, not a live child-process test: production runner uses fixed
  // /discovery-work and pinned binaries, neither of which is provisioned on the host.
});
