import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { auditDependencies } from "../dist/dependency-audit.js";

const manifest = { name: "fixture", dependencies: { example: "1.2.3" } };
const lockfile = {
  lockfileVersion: 3,
  packages: {
    "": manifest,
    "node_modules/example": {
      version: "1.2.3",
      resolved: "https://registry.npmjs.org/example/-/example-1.2.3.tgz",
    },
  },
};

async function fixture(t, lock = lockfile) {
  const project = await mkdtemp(join(tmpdir(), "sapphire-audit-test-"));
  t.after(() => rm(project, { recursive: true, force: true }));
  await writeFile(join(project, "package.json"), JSON.stringify(manifest));
  if (lock) await writeFile(join(project, "package-lock.json"), JSON.stringify(lock));
  return project;
}

function npmReport(vulnerabilities = {}) {
  return JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities,
    metadata: { vulnerabilities: { total: Object.keys(vulnerabilities).length } },
  });
}

test("reports clean only after a valid completed audit", async t => {
  const project = await fixture(t);
  const result = await auditDependencies(project, "", async snapshot => {
    assert.notEqual(snapshot, project);
    assert.deepEqual(JSON.parse(await readFile(join(snapshot, "package-lock.json"), "utf8")), lockfile);
    return { stdout: npmReport(), exitCode: 0 };
  });
  assert.equal(result.status, "clean");
  assert.equal(result.locked_package_instances, 1);
  assert.match(result.lockfile_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(result.findings, []);
});

test("retains lockfile versions, advisories and the suggested update", async t => {
  const project = await fixture(t);
  const report = npmReport({
    example: {
      severity: "high",
      isDirect: true,
      nodes: ["node_modules/example"],
      via: [{
        source: 123,
        title: "Fixture advisory",
        url: "https://example.test/advisory",
        severity: "high",
        range: "<1.2.4",
      }],
      fixAvailable: { name: "example", version: "1.2.4", isSemVerMajor: false },
    },
  });
  const result = await auditDependencies(project, "", async () => ({ stdout: report, exitCode: 1 }));
  assert.equal(result.status, "findings");
  assert.deepEqual(result.findings[0].instances, [{ path: "node_modules/example", version: "1.2.3" }]);
  assert.equal(result.findings[0].advisories[0].id, "npm:123");
  assert.deepEqual(result.findings[0].suggested_update, { package: "example", version: "1.2.4", major_upgrade: false });
});

test("missing or stale lockfiles never reach npm", async t => {
  let started = false;
  const runner = async () => {
    started = true;
    return { stdout: npmReport(), exitCode: 0 };
  };
  const missing = await fixture(t, null);
  const stale = await fixture(t, { ...lockfile, packages: { ...lockfile.packages, "": {} } });
  const truncated = await fixture(t, { ...lockfile, packages: { "": manifest } });
  for (const directory of [missing, stale, truncated]) {
    const result = await auditDependencies(directory, "", runner);
    assert.equal(result.status, "incomplete");
    assert.equal(result.reason, "missing_unreadable_or_unsupported_input");
  }
  assert.equal(started, false);
});

test("a registry error or malformed npm output is incomplete", async t => {
  const project = await fixture(t);
  const network = await auditDependencies(project, "", async () => { throw new Error("timeout"); });
  assert.equal(network.status, "incomplete");
  assert.equal(network.reason, "npm_audit_failed");

  for (const stdout of ["not json", JSON.stringify({ error: { code: "E500" } }), npmReport()]) {
    const result = await auditDependencies(project, "", async () => ({ stdout, exitCode: 1 }));
    assert.equal(result.status, "incomplete");
    assert.equal(result.reason, "invalid_npm_audit_report");
  }
});
