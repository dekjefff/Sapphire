import test from "node:test";
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import Fastify from "fastify";
import { registerZapImport, zapSummary } from "../dist/zap-import.js";

const id = "6d8ad44a-4594-42dc-af19-4d1e98f95e73";
const revision = "7d8ad44a-4594-42dc-af19-4d1e98f95e73";
const path = `/assessments/${id}/zap-report`;

test("offline import persists only normalized data, pages output, and preserves accepted data after failures", async (t) => {
  let value = null;
  let failSave = false;
  const store = {
    async save(assessmentId, report, source_sha256) {
      if (failSave) throw new Error("secret database detail");
      if (assessmentId !== id) return null;
      value = { report, source_sha256, imported_at: new Date("2026-01-01T00:00:00Z"), revision_id: revision };
      return value;
    },
    async load(assessmentId) { return { exists: assessmentId === id, value: assessmentId === id ? value : null }; },
  };
  const app = Fastify();
  await app.register(async (scope) => registerZapImport(scope, store));
  t.after(() => app.close());
  assert.deepEqual(zapSummary(value), { status: "missing" });
  assert.equal((await app.inject({ method: "GET", url: `${path}/findings` })).statusCode, 404);
  const secret = "sensitive-report-sentinel";
  const report = { "@version": "2.16.1", afPlanWarns: [secret], site: [{ alerts: [{ pluginid: "10038", riskcode: "2", instances: [
    { method: "GET", uri: secret, "response-header": `HTTP/1.1 200 OK\r\nSet-Cookie: ${secret}\r\n` },
    { method: "POST", evidence: secret },
  ] }] }] };
  const submitted = Buffer.from(`  ${JSON.stringify(report)}
`);
  const digest = createHash("sha256").update(submitted).digest("hex");
  const accepted = await app.inject({ method: "POST", url: path, headers: { "content-type": "application/json" }, payload: submitted });
  assert.equal(accepted.statusCode, 200);
  assert.deepEqual(accepted.json(), { status: "imported", revision_id: revision, source_sha256: digest, imported_at: "2026-01-01T00:00:00.000Z", tool: "zap", zap_version: "2.16.1", coverage: "incomplete", coverage_reasons: ["zap_plan_warnings"], finding_count: 1 });
  assert.equal(JSON.stringify(value).includes(secret), false);
  assert.equal(zapSummary({ ...value, source_sha256: null }).source_sha256, null);
  const findings = await app.inject({ method: "GET", url: `${path}/findings?limit=1&offset=0` });
  assert.equal(findings.statusCode, 200);
  assert.deepEqual(findings.json().items, [{ ruleId: "10038", severity: "medium", rawPointer: "/site/0/alerts/0", instance_count: 2 }]);
  const instances = await app.inject({ method: "GET", url: `${path}/findings/0/instances?limit=1&offset=1&revision_id=${revision}` });
  assert.deepEqual(instances.json().items, [{ rawPointer: "/site/0/alerts/0/instances/1", method: "POST", statusCode: null }]);
  assert.equal((await app.inject({ method: "GET", url: `${path}/findings/0/instances?revision_id=${id}` })).statusCode, 409);
  assert.equal((await app.inject({ method: "GET", url: `${path}/findings/0/instances` })).statusCode, 400);
  assert.equal((await app.inject({ method: "GET", url: `${path}/findings?limit=101` })).statusCode, 400);
  const previous = JSON.stringify(value);
  for (const payload of ['{"broken":', Buffer.from([0xc3, 0x28]), JSON.stringify({ "@version": "2.16.1" })]) {
    const response = await app.inject({ method: "POST", url: path, headers: { "content-type": "application/json" }, payload });
    assert.equal(response.statusCode, 422);
    assert.equal(JSON.stringify(value), previous);
    assert.equal(response.body.includes(secret), false);
  }
  failSave = true;
  const failure = await app.inject({ method: "POST", url: path, payload: report });
  assert.equal(failure.statusCode, 503);
  assert.equal(failure.body.includes("secret"), false);
  assert.equal(JSON.stringify(value), previous);
  const large = await app.inject({ method: "POST", url: path, headers: { "content-type": "application/json" }, payload: Buffer.alloc(10 * 1024 * 1024 + 1) });
  assert.equal(large.statusCode, 413);
  assert.equal(JSON.stringify(value), previous);

  failSave = false;
  const query = `passive_run_id=${revision}&capture_exchanges=2&capture_origins=1`;
  const passive = await app.inject({ method: "POST", url: `${path}?${query}`, payload: report });
  assert.equal(passive.statusCode, 200);
  assert.deepEqual(passive.json().passive_capture, {
    source: "cli_reported", run_id: revision, recorded_exchanges: 2, recorded_origins: 1, authentication: "unverified",
  });
  assert.deepEqual(value.report.passiveCapture, passive.json().passive_capture);
  assert.equal(passive.json().source_sha256, createHash("sha256").update(JSON.stringify(report)).digest("hex"));

  const acceptedPassive = JSON.stringify(value);
  const invalid = await app.inject({ method: "POST", url: `${path}?${query}&capture_origins=3`, payload: report });
  assert.equal(invalid.statusCode, 400);
  assert.equal(JSON.stringify(value), acceptedPassive);
});

test("empty imported report has unknown coverage and missing assessment is rejected", async (t) => {
  const store = { async save(assessmentId, report, source_sha256) { return assessmentId === id ? { report, source_sha256, imported_at: new Date(0), revision_id: revision } : null; }, async load() { return { exists: false, value: null }; } };
  const app = Fastify();
  await app.register(async (scope) => registerZapImport(scope, store));
  t.after(() => app.close());
  const report = { "@version": "2.16.1", site: [] };
  const result = await app.inject({ method: "POST", url: path, payload: report });
  assert.equal(result.json().coverage, "unknown");
  assert.equal(result.json().finding_count, 0);
  const missing = await app.inject({ method: "POST", url: "/assessments/00000000-0000-4000-8000-000000000000/zap-report", payload: report });
  assert.equal(missing.statusCode, 404);
});
