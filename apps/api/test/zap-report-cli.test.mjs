import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../dist/zap-report-cli.js", import.meta.url));

function runReport(t, input) {
  const folder = mkdtempSync(join(tmpdir(), "sapphire-zap-report-"));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const report = join(folder, "report.json");
  writeFileSync(report, Buffer.isBuffer(input) ? input : JSON.stringify(input));
  const result = spawnSync(process.execPath, [cli, report], { encoding: "utf8" });
  assert.ifError(result.error);
  return result;
}

test("exports rule provenance and allowlisted HTTP metadata", (t) => {
  const secret = "sentinel-sensitive-value";
  const report = {
    "@version": "2.16.1",
    site: [{
      "@name": `https://${secret}.test`,
      alerts: [{
        pluginid: "10038",
        riskcode: "2",
        alert: secret,
        desc: secret,
        instances: [{
          uri: `https://example.test/${secret}?token=${secret}`,
          method: "GET",
          "request-header": `GET /${secret} HTTP/1.1\r\nAuthorization: Bearer ${secret}\r\n`,
          "request-body": secret,
          "response-header": `HTTP/2 200 OK\r\nSet-Cookie: sid=${secret}\r\n`,
          "response-body": secret,
          evidence: secret,
        }, {
          method: secret,
          "response-header": `invalid status ${secret}`,
        }],
      }],
    }],
  };
  const { status, stdout, stderr } = runReport(t, report);
  assert.equal(status, 0, stderr);
  assert.equal(stderr, "");
  assert.equal(stdout.includes(secret), false);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.tool, "zap");
  assert.equal(parsed.zapVersion, "2.16.1");
  assert.equal(parsed.coverage, "unknown");
  assert.deepEqual(parsed.findings, [{
    ruleId: "10038",
    severity: "medium",
    rawPointer: "/site/0/alerts/0",
    instances: [
      { rawPointer: "/site/0/alerts/0/instances/0", method: "GET", statusCode: 200 },
      { rawPointer: "/site/0/alerts/0/instances/1", method: null, statusCode: null },
    ],
  }]);
});

test("distinguishes unavailable coverage and recorded ZAP errors or warnings", (t) => {
  for (const diagnostic of [
    { afPlanErrors: [], afPlanWarns: [], expected: [] },
    { afPlanErrors: ["secret in diagnostic"], expected: ["zap_plan_errors"] },
    { afPlanWarns: ["secret in diagnostic"], expected: ["zap_plan_warnings"] },
  ]) {
    const { expected, ...fields } = diagnostic;
    const { status, stdout, stderr } = runReport(t, { "@version": "2.16.1", site: [], ...fields });
    assert.equal(status, 0, stderr);
    assert.equal(stdout.includes("secret in diagnostic"), false);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.coverage, expected.length ? "incomplete" : "unknown");
    assert.deepEqual(parsed.coverageReasons, expected);
    assert.deepEqual(parsed.findings, []);
  }
});

test("accepts Traditional JSON instances without response headers", (t) => {
  const { status, stdout, stderr } = runReport(t, {
    "@version": "Dev Build",
    site: [{ alerts: [{ pluginid: "10038", riskcode: "0", instances: [{ method: "HEAD" }] }] }],
  });
  assert.equal(status, 0, stderr);
  const { findings: [finding] } = JSON.parse(stdout);
  assert.equal(finding.severity, "info");
  assert.deepEqual(finding.instances, [
    { rawPointer: "/site/0/alerts/0/instances/0", method: "HEAD", statusCode: null },
  ]);
});

test("handles upstream-shaped empty arrays and only reads the first status line", (t) => {
  const report = {
    "@programName": "ZAP", "@version": "2.16.1", "@generated": "date", created: "date",
    site: [
      { "@name": "https://example.test", "@host": "example.test", "@port": "443", "@ssl": "true", alerts: [] },
      { "@name": "https://other.test", alerts: [{ pluginid: "10038", riskcode: "2", instances: [
        { method: "GET", "response-header": "invalid\r\nHTTP/1.1 200 OK\r\n" },
        { method: "POST", "response-header": "HTTP/1.1 204\r\n\r\n" },
        { method: "GET" },
      ] }] },
    ],
  };
  const { status, stdout, stderr } = runReport(t, report);
  assert.equal(status, 0, stderr);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.coverage, "unknown");
  assert.deepEqual(parsed.findings[0].instances.map((instance) => instance.statusCode), [null, 204, null]);
  const empty = runReport(t, { "@version": "2.16.1", site: [] });
  assert.equal(empty.status, 0, empty.stderr);
  assert.deepEqual(JSON.parse(empty.stdout).findings, []);
});

test("rejects missing required arrays and aggregate alert overflow", (t) => {
  for (const report of [
    { "@version": "2.16.1" },
    { "@version": "2.16.1", site: [{}] },
    { "@version": "2.16.1", site: [{ alerts: [{ pluginid: "10038", riskcode: "2" }] }] },
    { "@version": "2.16.1", site: [
      { alerts: Array.from({ length: 10001 }, () => ({ pluginid: "1", riskcode: "0", instances: [] })) },
      { alerts: Array.from({ length: 10000 }, () => ({ pluginid: "1", riskcode: "0", instances: [] })) },
    ] },
  ]) {
    const { status, stdout, stderr } = runReport(t, report);
    assert.equal(status, 1);
    assert.equal(stdout, "");
    assert.equal(stderr.trim(), "zap_report_invalid_or_unsupported");
  }
});

test("rejects directories as report inputs", (t) => {
  const folder = mkdtempSync(join(tmpdir(), "sapphire-zap-directory-"));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const result = spawnSync(process.execPath, [cli, folder], { encoding: "utf8" });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr.trim(), "zap_report_read_failed");
});

test("reports invalid JSON, UTF-8, or structure without leaking input", (t) => {
  for (const input of [
    Buffer.from('{"secret": unquoted}'),
    Buffer.from([0xc3, 0x28]),
    { "@version": "2.16.1", site: [{ alerts: { secret: "invalid" } }] },
  ]) {
    const { status, stdout, stderr } = runReport(t, input);
    assert.equal(status, 1);
    assert.equal(stdout, "");
    assert.equal(stderr.trim(), "zap_report_invalid_or_unsupported");
  }
});

test("rejects reports beyond the byte limit", (t) => {
  const { status, stdout, stderr } = runReport(t, Buffer.alloc(10 * 1024 * 1024 + 1));
  assert.equal(status, 1);
  assert.equal(stdout, "");
  assert.equal(stderr.trim(), "zap_report_size_limit");
});
