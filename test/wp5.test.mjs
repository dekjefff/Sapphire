import test, { after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const roots = [];
let coordinator, normalizer, coverage, scopeApi, contracts, adapters;
try {
  const paths = [
    resolve(root, "apps/api/dist/discovery/coordinator.js"), resolve(root, "apps/api/dist/discovery/normalizer.js"),
    resolve(root, "apps/api/dist/discovery/coverage.js"), resolve(root, "apps/api/dist/discovery-scope-policy.js"),
    resolve(root, "apps/api/dist/discovery-contracts.js"), resolve(root, "apps/api/dist/discovery/adapters.js"),
  ];
  await Promise.all(paths.map(access));
  [coordinator, normalizer, coverage, scopeApi, contracts, adapters] = await Promise.all(paths.map(path => import(pathToFileURL(path))));
} catch { /* explicit per-test skip if build output is absent */ }
after(async () => Promise.all(roots.map(path => rm(path, { recursive: true, force: true }))));

async function tempRoot() { const path = await mkdtemp(join(tmpdir(), "sapphire-wp5-")); roots.push(path); return path; }
function available(t) {
  if (coordinator && normalizer && coverage && scopeApi && contracts && adapters) return true;
  t.skip("WP5 API dist modules unavailable; run npm --prefix apps/api run build"); return false;
}
function makeInputs() {
  const assessmentId = randomUUID(), scopeId = randomUUID(), toolRunId = randomUUID();
  const scope = scopeApi.createDiscoveryScope({ scope_id: scopeId, assessment_id: assessmentId, origin: "http://app.local:3000", path_mode: "prefix", path_prefixes: ["/api"], pinned_ips: ["192.0.2.10"], policy_revision: "wp5-test", authorization_actor: "WP5 tests", authorized_at: "2026-01-01T00:00:00.000Z", expires_at: "2030-01-01T00:00:00.000Z" });
  const budget = { ...contracts.DEFAULT_DISCOVERY_BUDGET, profile_id: "wp5-profile" };
  const task = { schema_version: 1, assessment_id: assessmentId, tool_run_id: toolRunId, scope_id: scopeId, scope_policy_sha256: scope.policy_sha256, tool: "httpx", seed_url: "http://app.local:3000/api", budget_profile_id: budget.profile_id, cancellation_ref: toolRunId };
  return { assessmentId, scopeId, toolRunId, scope, budget, task };
}
function configHash(task, scope, budget, toolVersion = coordinator.DISCOVERY_TOOL_VERSIONS[task.tool], adapterVersion = coordinator.DISCOVERY_ADAPTER_VERSION) {
  const argv = task.tool === "httpx" ? adapters.buildHttpxArgv(task, budget) : adapters.buildKatanaArgv(task, scope, budget);
  const proxy = adapters.buildPolicyProxyUrl(task);
  return coordinator.sha256(JSON.stringify({ tool: task.tool, version: toolVersion, adapter: adapterVersion, argv: argv.map(value => value === task.seed_url ? "<authorized-seed>" : value === proxy ? "<policy-proxy>" : value), budget }));
}
function resultFor(ctx, overrides = {}) {
  const tool = overrides.tool ?? ctx.task.tool;
  const toolVersion = overrides.tool_version ?? coordinator.DISCOVERY_TOOL_VERSIONS[tool];
  const adapterVersion = overrides.adapter_version ?? coordinator.DISCOVERY_ADAPTER_VERSION;
  return {
    schema_version: 1, assessment_id: ctx.assessmentId, tool_run_id: ctx.toolRunId, tool, tool_version: toolVersion,
    adapter_version: adapterVersion, config_sha256: overrides.config_sha256 ?? configHash({ ...ctx.task, tool }, ctx.scope, ctx.budget, toolVersion, adapterVersion),
    scope_policy_sha256: overrides.scope_policy_sha256 ?? ctx.scope.policy_sha256, status: "completed", coverage_status: "complete", failure_reason_code: null,
    counters: { urls_seen: 1, requests_sent: 1, responses_received: 1, response_bytes: 16, endpoints_persisted: 1, redirects_denied: 0, policy_denials: 0 },
    started_at: "2026-11-18T00:00:00.000Z", finished_at: "2026-11-18T00:00:01.000Z",
    artifacts: [{ artifact_id: randomUUID(), artifact_kind: tool === "httpx" ? "httpx_json" : "katana_json", sha256: "a".repeat(64), byte_size: 16 }],
    ...overrides,
  };
}
async function writeResult(ctx, value) {
  const dir = join(ctx.root, "results", ctx.toolRunId); await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "result.json"), JSON.stringify(value));
}

test("WP5 writes atomic validated task, scope and budget queue inputs", async t => {
  if (!available(t)) return;
  const ctx = { ...makeInputs(), root: await tempRoot() };
  const requestPath = await coordinator.writeDiscoveryInputs(ctx.root, ctx.task, ctx.scope, ctx.budget);
  assert.equal(requestPath, join(ctx.root, "requests", `${ctx.toolRunId}.json`));
  assert.deepEqual(JSON.parse(await readFile(requestPath, "utf8")), ctx.task);
  assert.deepEqual(JSON.parse(await readFile(join(ctx.root, "scopes", `${ctx.scopeId}.json`), "utf8")), ctx.scope);
  assert.deepEqual(JSON.parse(await readFile(join(ctx.root, "budgets", `${ctx.budget.profile_id}.json`), "utf8")), ctx.budget);
  assert.equal((await (await import("node:fs/promises")).readdir(join(ctx.root, "requests"))).some(name => name.endsWith(".tmp")), false);
  await assert.rejects(coordinator.writeDiscoveryInputs(ctx.root, { ...ctx.task, scope_policy_sha256: "b".repeat(64) }, ctx.scope, ctx.budget), /discovery_input_invalid/);
  await assert.rejects(coordinator.writeDiscoveryInputs(ctx.root, { ...ctx.task, tool_run_id: "../outside" }, ctx.scope, ctx.budget));
});

test("WP5 normalizer emits queryless canonical GET endpoints and merges duplicates", async t => {
  if (!available(t)) return;
  const ctx = makeInputs();
  const input = [
    JSON.stringify({ url: "http://app.local:3000/api/items?id=secret-one", status_code: 200, content_type: "application/json", title: "Items" }),
    JSON.stringify({ url: "http://app.local:3000/api/items?token=secret-two", status_code: 200, content_length: 23, title: "Items" }),
    JSON.stringify({ url: "http://outside.local/api/items?secret=outside" }),
  ].join("\n");
  const rows = normalizer.normalizeDiscoveryJsonl(input, { tool: "httpx", assessmentId: ctx.assessmentId, toolRunId: ctx.toolRunId, artifactId: randomUUID(), scope: ctx.scope, toolVersion: "1.12.0", configSha256: "c".repeat(64), observedAt: "2026-11-18T00:00:02.000Z" });
  assert.equal(rows.length, 1); assert.equal(rows[0].endpoint.path, "/api/items"); assert.equal(rows[0].endpoint.method, "GET");
  assert.equal(rows[0].endpoint.first_seen_at, "2026-11-18T00:00:02.000Z"); assert.equal(rows[0].endpoint.last_seen_at, "2026-11-18T00:00:02.000Z");
  assert.equal(rows[0].raw_pointer, "/line/1"); assert.ok(!JSON.stringify(rows).includes("secret"));
});

test("WP5 missing and malformed result files are rejected without a long wait", async t => {
  if (!available(t)) return;
  const ctx = { ...makeInputs(), root: await tempRoot() };
  await coordinator.writeDiscoveryInputs(ctx.root, ctx.task, ctx.scope, ctx.budget);
  const resultDir = join(ctx.root, "results", ctx.toolRunId); await mkdir(resultDir, { recursive: true });
  const waiting = coordinator.waitForDiscoveryResult(ctx.root, ctx.task, ctx.budget, async () => false);
  await new Promise(resolve => setTimeout(resolve, 25));
  await writeFile(join(resultDir, "result.json"), "{malformed");
  await assert.rejects(waiting, /discovery_result_invalid/);
});

test("WP5 rejects result identity, scope, tool version, adapter and config mismatches", async t => {
  if (!available(t)) return;
  const variants = [{ status: "running", coverage_status: "pending" }, { assessmentId: randomUUID() }, { tool_run_id: randomUUID() }, { tool: "katana" }, { tool_version: "9.9.9" }, { adapter_version: "9.9.9" }, { scope_policy_sha256: "b".repeat(64) }, { config_sha256: "b".repeat(64) }, { artifacts: [] }];
  for (const change of variants) {
    const ctx = { ...makeInputs(), root: await tempRoot() };
    await coordinator.writeDiscoveryInputs(ctx.root, ctx.task, ctx.scope, ctx.budget);
    await writeResult(ctx, resultFor(ctx, change));
    await assert.rejects(coordinator.waitForDiscoveryResult(ctx.root, ctx.task, ctx.budget, async () => false), /discovery_result_invalid/);
  }
});

test("WP5 artifact verifier rejects traversal, symlink, type, size and hash mismatches", async t => {
  if (!available(t)) return;
  const ctx = makeInputs(); ctx.root = await tempRoot();
  const bytes = Buffer.from('{"url":"http://app.local:3000/api"}\n');
  const dir = join(ctx.root, "results", ctx.toolRunId); await mkdir(dir, { recursive: true });
  const artifactPath = join(dir, "httpx.jsonl"); await writeFile(artifactPath, bytes);
  const descriptor = { artifact_id: randomUUID(), artifact_kind: "httpx_json", sha256: coordinator.sha256(bytes), byte_size: bytes.length };
  const result = resultFor(ctx);
  assert.deepEqual(await coordinator.verifyDiscoveryArtifact(ctx.root, result, descriptor), bytes);
  await assert.rejects(coordinator.verifyDiscoveryArtifact(ctx.root, result, { ...descriptor, byte_size: bytes.length + 1 }), /artifact_metadata_invalid/);
  await assert.rejects(coordinator.verifyDiscoveryArtifact(ctx.root, result, { ...descriptor, artifact_kind: "katana_json" }), /artifact_metadata_invalid/);
  await assert.rejects(coordinator.verifyDiscoveryArtifact(ctx.root, result, { ...descriptor, sha256: "f".repeat(64) }), /artifact_hash_mismatch/);
  await assert.rejects(coordinator.verifyDiscoveryArtifact(ctx.root, { ...result, tool_run_id: "../../escape" }, descriptor), /artifact_path_invalid/);
  const linked = join(dir, "katana.jsonl"); await symlink(artifactPath, linked);
  await assert.rejects(coordinator.verifyDiscoveryArtifact(ctx.root, { ...result, tool: "katana" }, { ...descriptor, artifact_kind: "katana_json" }), /artifact_metadata_invalid/);
});

test("WP5 preserves partial failed endpoints and artifact evidence", async t => {
  if (!available(t)) return;
  const ctx = { ...makeInputs(), root: await tempRoot() }; await coordinator.writeDiscoveryInputs(ctx.root, ctx.task, ctx.scope, ctx.budget);
  const bytes = Buffer.from(JSON.stringify({ url: "http://app.local:3000/api/partial?token=secret", status_code: 503, content_length: 30 }) + "\n");
  const descriptor = { artifact_id: randomUUID(), artifact_kind: "httpx_json", sha256: coordinator.sha256(bytes), byte_size: bytes.length };
  await mkdir(join(ctx.root, "results", ctx.toolRunId), { recursive: true }); await writeFile(join(ctx.root, "results", ctx.toolRunId, "httpx.jsonl"), bytes);
  const partial = resultFor(ctx, { status: "failed", coverage_status: "incomplete", failure_reason_code: "timeout", artifacts: [descriptor] }); await writeResult(ctx, partial);
  const accepted = await coordinator.waitForDiscoveryResult(ctx.root, ctx.task, ctx.budget, async () => false);
  assert.equal(accepted.status, "failed"); assert.deepEqual(await coordinator.verifyDiscoveryArtifact(ctx.root, accepted, descriptor), bytes);
  const rows = normalizer.normalizeDiscoveryJsonl(bytes.toString(), { tool: "httpx", assessmentId: ctx.assessmentId, toolRunId: ctx.toolRunId, artifactId: descriptor.artifact_id, scope: ctx.scope, toolVersion: "1.12.0", configSha256: accepted.config_sha256, observedAt: "2026-11-18T00:00:03.000Z" });
  assert.equal(rows.length, 1); assert.equal(rows[0].endpoint.status_code, 503); assert.ok(!JSON.stringify(rows).includes("secret"));
});

test("WP5 cancellation markers are written before and during result polling", async t => {
  if (!available(t)) return;
  const before = { ...makeInputs(), root: await tempRoot() }; await coordinator.writeDiscoveryInputs(before.root, before.task, before.scope, before.budget); await mkdir(join(before.root, "cancel"), { recursive: true });
  await writeResult(before, resultFor(before, { status: "cancelled", coverage_status: "incomplete", failure_reason_code: "cancelled" }));
  const beforeResult = await coordinator.waitForDiscoveryResult(before.root, before.task, before.budget, async () => true);
  assert.equal(beforeResult.status, "cancelled"); assert.ok((await readFile(join(before.root, "cancel", before.toolRunId), "utf8")).includes("cancel"));

  const during = { ...makeInputs(), root: await tempRoot() }; await coordinator.writeDiscoveryInputs(during.root, during.task, during.scope, during.budget); await mkdir(join(during.root, "cancel"), { recursive: true });
  const resultDir = join(during.root, "results", during.toolRunId); await mkdir(resultDir, { recursive: true });
  const waiting = coordinator.waitForDiscoveryResult(during.root, during.task, during.budget, async () => true);
  await new Promise(resolve => setTimeout(resolve, 25));
  assert.ok((await readFile(join(during.root, "cancel", during.toolRunId), "utf8")).includes("cancel"));
  await writeResult(during, resultFor(during, { status: "cancelled", coverage_status: "incomplete", failure_reason_code: "cancelled" }));
  assert.equal((await waiting).status, "cancelled");
});

test("WP5 gateway event reader validates caps, strict fields, known reasons and symlink safety", async t => {
  if (!available(t)) return;
  const ctx = { ...makeInputs(), root: await tempRoot() }; const dir = join(ctx.root, "gateway-events"); await mkdir(dir, { recursive: true });
  const file = join(dir, `${ctx.toolRunId}.jsonl`);
  assert.deepEqual(await coordinator.readGatewayEvents(ctx.root, ctx.toolRunId), { reason: null, denials: 0 });
  await writeFile(file, `${JSON.stringify({ timestamp: "2026-11-18T00:00:00.000Z", reason_code: "redirect_denied" })}\n`);
  assert.deepEqual(await coordinator.readGatewayEvents(ctx.root, ctx.toolRunId), { reason: "redirect_denied", denials: 1 });
  await writeFile(file, `${JSON.stringify({ timestamp: "2026-11-18T00:00:00.000Z", reason_code: "made_up" })}\n`);
  await assert.rejects(coordinator.readGatewayEvents(ctx.root, ctx.toolRunId), /gateway_events_invalid/);
  await writeFile(file, `${JSON.stringify({ timestamp: "2026-11-18T00:00:00.000Z", reason_code: "redirect_denied", url: "http://secret" })}\n`);
  await assert.rejects(coordinator.readGatewayEvents(ctx.root, ctx.toolRunId), /gateway_events_invalid/);
  await writeFile(file, Array.from({ length: 257 }, () => JSON.stringify({ timestamp: "2026-11-18T00:00:00.000Z", reason_code: "cancelled" })).join("\n"));
  await assert.rejects(coordinator.readGatewayEvents(ctx.root, ctx.toolRunId), /gateway_events_invalid/);
  await writeFile(file, "x".repeat(64 * 1024 + 1)); await assert.rejects(coordinator.readGatewayEvents(ctx.root, ctx.toolRunId), /gateway_events_invalid/);
  await rm(file); const other = join(dir, "event-source.jsonl"); await writeFile(other, "{}"); await symlink(other, file);
  await assert.rejects(coordinator.readGatewayEvents(ctx.root, ctx.toolRunId), /gateway_events_invalid/);
});

test("WP5 status and intake gap reason codes enforce incomplete coverage", async t => {
  if (!available(t)) return;
  const complete = resultFor(makeInputs());
  assert.equal(contracts.DiscoveryResultSchema.safeParse(complete).success, true);
  assert.equal(contracts.DiscoveryResultSchema.safeParse({ ...complete, status: "cancelled", coverage_status: "complete" }).success, false);
  assert.equal(contracts.DiscoveryResultSchema.safeParse({ ...complete, status: "completed", coverage_status: "pending" }).success, false);
  for (const code of ["generated_content_skipped", "intake_link_skipped", "route_parser_limit", "route_source_parse_warning"]) assert.equal(coverage.hasCoverageGaps([code]), true, code);
  for (const code of ["intake_limit_exceeded", "intake_archive_malformed"]) assert.equal(coverage.hasCoverageGaps([code]), false, code);
  assert.equal(coverage.hasCoverageGaps(["route_matched", "unknown_reason"]), false);
  const worker = await readFile(resolve(root, "apps/api/src/worker.ts"), "utf8");
  assert.match(worker, /complete \? "completed" : "failed"/);
  assert.match(worker, /coverage_status=\$3/);
  assert.match(worker, /reason_codes: \[semgrep\.failureCode, trivy\.failureCode, discovery\?\.httpx\.failure, discovery\?\.katana\?\.failure, \.\.\.intakeReasonCodes\.filter\(\(code\) => hasCoverageGaps\(\[code\]\)\)\]/);
});

test("WP5 requires completed HTTPX origin verification before Katana", async () => {
  const source = await readFile(resolve(root, "apps/api/src/discovery/runner.ts"), "utf8");
  assert.match(source, /task\.tool === "katana" && !\(await verifyHttpxOrigin\(task, scope\)\)/);
  assert.match(source, /value\.scope_policy_sha256 === scope\.policy_sha256/);
  assert.match(source, /value\.status === "completed"/);
  assert.match(source, /value\.httpx_version === VERSIONS\.httpx/);
});

