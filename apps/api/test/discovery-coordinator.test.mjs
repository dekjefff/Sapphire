import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createDiscoveryScope } from "../dist/discovery-scope-policy.js";
import { DEFAULT_DISCOVERY_BUDGET } from "../dist/discovery-contracts.js";
import { normalizeDiscoveryJsonl } from "../dist/discovery/normalizer.js";
import { readGatewayEvents, verifyDiscoveryArtifact, waitForDiscoveryResult, writeDiscoveryInputs } from "../dist/discovery/coordinator.js";
import { buildHttpxArgv, buildPolicyProxyUrl } from "../dist/discovery/adapters.js";
import { hasCoverageGaps } from "../dist/discovery/coverage.js";
import { refreshRouteMatches } from "../dist/discovery/matching.js";

const scope = createDiscoveryScope({
  scope_id: "f42c9bd3-560d-4a16-9660-d92b8c163c02",
  assessment_id: "17db3dd5-2552-4686-bf76-7e607ef85300",
  origin: "http://app.local:3000", path_mode: "prefix", path_prefixes: ["/"], pinned_ips: ["127.0.0.1"],
  policy_revision: "fixture-v1", authorization_actor: "test", authorized_at: "2026-11-18T00:00:00.000Z", expires_at: "2026-11-19T00:00:00.000Z",
});
const runId = "be0573b4-b78e-4567-85f5-a57a0b16886e";
const hash = (value) => createHash("sha256").update(value).digest("hex");

test("normalizer removes query data and deduplicates canonical GET endpoint paths", () => {
  const rows = normalizeDiscoveryJsonl([
    JSON.stringify({ url: "http://app.local:3000/api/users?token=SECRET", status_code: 200, title: "Users" }),
    JSON.stringify({ url: "http://app.local:3000/api/users?other=value", status_code: 200, title: "Users" }),
  ].join("\n") + "\n", {
    tool: "katana", assessmentId: scope.assessment_id, toolRunId: runId,
    artifactId: "a4f2d8fc-5051-4aa6-aa94-3a31efc276d0", scope, toolVersion: "1.8.0",
    configSha256: "a".repeat(64), observedAt: "2026-11-18T01:02:03.000Z",
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].endpoint.path, "/api/users");
  assert.equal(rows[0].endpoint.method, "GET");
  assert.equal(JSON.stringify(rows).includes("SECRET"), false);
  assert.equal(rows[0].raw_pointer, "/line/1");
});

test("shared reason catalog keeps incomplete intake coverage from becoming complete", () => {
  assert.equal(hasCoverageGaps(["generated_content_skipped"]), true);
  assert.equal(hasCoverageGaps(["intake_link_skipped", "route_source_parse_warning"]), true);
  assert.equal(hasCoverageGaps(["routes_none", "route_matched"]), false);
});

test("refreshing with zero runtime endpoints replaces matches with source-only rows", async () => {
  const statements = [];
  const client = {
    async query(sql, values = []) {
      statements.push({ sql, values });
      if (sql.includes("FROM discovered_routes")) return { rows: [{ id: "7e25f550-2d79-4fcb-aae2-944f75013ee0", method: "GET", path: "/health", source_file: "src/routes.ts", source_line: 9 }] };
      if (sql.includes("FROM runtime_endpoints")) return { rows: [] };
      return { rows: [] };
    },
  };
  await refreshRouteMatches(client, scope.assessment_id);
  assert.equal(statements.some(({ sql }) => sql.startsWith("DELETE FROM endpoint_route_matches")), true);
  const inserted = statements.find(({ sql }) => sql.startsWith("INSERT INTO endpoint_route_matches"));
  assert.ok(inserted);
  assert.equal(inserted.values[3], "source_only");
  assert.equal(inserted.values[5], "/health");
});

test("fabricated runner result validates task, inputs, gateway denial, and artifact hash", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sapphire-discovery-test-"));
  try {
    const task = {
      schema_version: 1, assessment_id: scope.assessment_id, tool_run_id: runId,
      scope_id: scope.scope_id, scope_policy_sha256: scope.policy_sha256, tool: "httpx",
      seed_url: "http://app.local:3000/", budget_profile_id: DEFAULT_DISCOVERY_BUDGET.profile_id, cancellation_ref: runId,
    };
    await writeDiscoveryInputs(root, task, scope, DEFAULT_DISCOVERY_BUDGET);
    const request = JSON.parse(await readFile(path.join(root, "requests", `${runId}.json`), "utf8"));
    assert.equal(request.scope_policy_sha256, scope.policy_sha256);
    const artifact = Buffer.from(`${JSON.stringify({ url: "http://app.local:3000/health", status_code: 200 })}\n`);
    const descriptor = { artifact_id: "a4f2d8fc-5051-4aa6-aa94-3a31efc276d0", artifact_kind: "httpx_json", sha256: hash(artifact), byte_size: artifact.length };
    const artifactDir = path.join(root, "results", runId);
    await mkdir(artifactDir, { recursive: true });
    await writeFile(path.join(artifactDir, "httpx.jsonl"), artifact);
    const argv = buildHttpxArgv(task, DEFAULT_DISCOVERY_BUDGET);
    const proxy = buildPolicyProxyUrl(task);
    const configSha = hash(JSON.stringify({ tool: "httpx", version: "1.12.0", adapter: "1.0.0", argv: argv.map((value) => value === task.seed_url ? "<authorized-seed>" : value === proxy ? "<policy-proxy>" : value), budget: DEFAULT_DISCOVERY_BUDGET }));
    const result = {
      schema_version: 1, assessment_id: scope.assessment_id, tool_run_id: runId, tool: "httpx", tool_version: "1.12.0",
      adapter_version: "1.0.0", config_sha256: configSha, scope_policy_sha256: scope.policy_sha256,
      status: "completed", coverage_status: "complete", failure_reason_code: null,
      counters: { urls_seen: 1, requests_sent: 1, responses_received: 1, response_bytes: 12, endpoints_persisted: 1, redirects_denied: 0, policy_denials: 0 },
      started_at: "2026-11-18T01:00:00.000Z", finished_at: "2026-11-18T01:00:01.000Z", artifacts: [descriptor],
    };
    await writeFile(path.join(artifactDir, "result.json"), JSON.stringify(result));
    const received = await waitForDiscoveryResult(root, task, DEFAULT_DISCOVERY_BUDGET, async () => false);
    assert.equal(received.tool_run_id, runId);
    assert.deepEqual(await verifyDiscoveryArtifact(root, received, descriptor), artifact);
    const eventDir = path.join(root, "gateway-events");
    await mkdir(eventDir);
    await writeFile(path.join(eventDir, `${runId}.jsonl`), JSON.stringify({ timestamp: "2026-11-18T01:00:01.000Z", reason_code: "redirect_denied" }) + "\n");
    assert.deepEqual(await readGatewayEvents(root, runId), { reason: "redirect_denied", denials: 1 });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
