import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createDiscoveryScope } from "../dist/discovery-scope-policy.js";
import { DEFAULT_DISCOVERY_BUDGET } from "../dist/discovery-contracts.js";
import { buildHttpxArgv, buildKatanaArgv } from "../dist/discovery/adapters.js";
import { parseHttpxJsonl, parseKatanaJsonl } from "../dist/discovery/parsers.js";

const scope = createDiscoveryScope({
  scope_id: "f42c9bd3-560d-4a16-9660-d92b8c163c02",
  assessment_id: "17db3dd5-2552-4686-bf76-7e607ef85300",
  origin: "http://app.local:3000",
  path_mode: "prefix",
  path_prefixes: ["/", "/api"],
  pinned_ips: ["127.0.0.1"],
  policy_revision: "fixture-v1",
  authorization_actor: "test",
  authorized_at: "2026-11-18T00:00:00.000Z",
  expires_at: "2026-11-19T00:00:00.000Z",
});
const taskBase = {
  schema_version: 1,
  assessment_id: scope.assessment_id,
  tool_run_id: "be0573b4-b78e-4567-85f5-a57a0b16886e",
  scope_id: scope.scope_id,
  scope_policy_sha256: scope.policy_sha256,
  seed_url: "http://app.local:3000/",
  budget_profile_id: "discovery-default-v1",
  cancellation_ref: "be0573b4-b78e-4567-85f5-a57a0b16886e",
};

test("tool argv is fixed, scoped to the gateway, GET-only, and excludes active options", () => {
  const httpx = buildHttpxArgv({ ...taskBase, tool: "httpx" }, DEFAULT_DISCOVERY_BUDGET);
  const katana = buildKatanaArgv({ ...taskBase, tool: "katana" }, scope, DEFAULT_DISCOVERY_BUDGET);
  assert.equal(httpx[httpx.indexOf("-method") + 1], "GET");
  assert.ok(httpx.includes("-proxy"));
  assert.ok(katana.includes("-disable-redirects"));
  assert.ok(katana.includes("-omit-body"));
  assert.ok(katana.includes("-max-domain-pages"));
  for (const argv of [httpx, katana]) {
    const normalized = argv.join(" ").toLowerCase();
    assert.match(normalized, /@discovery-gateway:8080/);
    assert.doesNotMatch(normalized, /headless|automatic-form|form-fill|auto-login|cookie|authorization|follow-redirect|known-files|\s-x\s+all/);
  }
});

test("httpx fixture keeps only bounded in-scope metadata and denies redirects", async () => {
  const fixture = await readFile(new URL("./fixtures/httpx.jsonl", import.meta.url), "utf8");
  const rows = parseHttpxJsonl(fixture, scope);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].url, "http://app.local:3000/health");
  assert.equal(rows[0].status_code, 200);
  assert.equal(rows[1].redirect_observed, true);
  assert.ok(!JSON.stringify(rows).includes("FIXTURE_SECRET_QUERY_SHOULD_NOT_PERSIST"));
  assert.ok(!JSON.stringify(rows).includes("outside.example"));
});

test("Katana fixture normalizes paths, strips query values, and retains only safe referrer path", async () => {
  const fixture = await readFile(new URL("./fixtures/katana.jsonl", import.meta.url), "utf8");
  const rows = parseKatanaJsonl(fixture, scope);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].url, "http://app.local:3000/api/users");
  assert.equal(rows[0].referrer_path, "/");
  assert.equal(rows[0].content_type, "application/json");
  assert.ok(!JSON.stringify(rows).includes("FIXTURE_SECRET_QUERY_SHOULD_NOT_PERSIST"));
});

test("malformed JSONL and oversized records fail closed", () => {
  assert.throws(() => parseHttpxJsonl("{not-json}\n", scope));
  assert.throws(() => parseKatanaJsonl(`${JSON.stringify({ url: `http://app.local:3000/${"x".repeat(70_000)}` })}\n`, scope));
});
