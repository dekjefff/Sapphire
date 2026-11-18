import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { DiscoveryBudgetProfileSchema, DiscoveryResultSchema, DiscoveryScopeSchema, DiscoveryTaskSchema, type DiscoveryBudgetProfile, type DiscoveryResult, type DiscoveryScope, type DiscoveryTask } from "../discovery-contracts.js";
import { isReasonCode } from "../reason-codes.js";
import { verifyDiscoveryScope } from "../discovery-scope-policy.js";
import { buildHttpxArgv, buildKatanaArgv, buildPolicyProxyUrl } from "./adapters.js";

export const DISCOVERY_ADAPTER_VERSION = "1.0.0";
export const DISCOVERY_TOOL_VERSIONS = { httpx: "1.12.0", katana: "1.8.0" } as const;
export const DISCOVERY_WAIT_MS = 150_000;
export const DISCOVERY_ARTIFACT_LIMIT = 8 * 1024 * 1024;
const EVENT_REASONS = new Set(["scope_invalid", "scope_expired", "scope_https_prefix_unsupported", "scope_path_denied", "scope_origin_denied", "dns_policy_rejected", "peer_ip_mismatch", "redirect_denied", "rate_budget_exhausted", "concurrency_budget_exhausted", "url_budget_exhausted", "byte_budget_exhausted", "timeout", "cancelled", "tool_failed"]);

export function sha256(bytes: string | Buffer): string { return createHash("sha256").update(bytes).digest("hex"); }
export function discoveryArtifactLeaf(tool: "httpx" | "katana"): string { return tool === "httpx" ? "httpx.jsonl" : "katana.jsonl"; }

function inside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
}

async function atomicJson(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o2770 });
  const temp = `${file}.${randomUUID()}.tmp`;
  await writeFile(temp, `${JSON.stringify(value)}\n`, { flag: "wx", mode: 0o660 });
  try { await rename(temp, file); } catch (error) { await rm(temp, { force: true }); throw error; }
}

export async function writeDiscoveryInputs(root: string, task: DiscoveryTask, scope: DiscoveryScope, budget: DiscoveryBudgetProfile): Promise<string> {
  const safeTask = DiscoveryTaskSchema.parse(task);
  const safeScope = DiscoveryScopeSchema.parse(scope);
  const safeBudget = DiscoveryBudgetProfileSchema.parse(budget);
  if (!verifyDiscoveryScope(safeScope) || safeTask.scope_id !== safeScope.scope_id || safeTask.assessment_id !== safeScope.assessment_id || safeTask.scope_policy_sha256 !== safeScope.policy_sha256 || safeTask.budget_profile_id !== safeBudget.profile_id) throw new Error("discovery_input_invalid");
  const scopePath = path.join(root, "scopes", `${safeScope.scope_id}.json`);
  const budgetPath = path.join(root, "budgets", `${safeBudget.profile_id}.json`);
  const requestPath = path.join(root, "requests", `${safeTask.tool_run_id}.json`);
  await Promise.all([atomicJson(scopePath, safeScope), atomicJson(budgetPath, safeBudget), mkdir(path.dirname(requestPath), { recursive: true, mode: 0o2770 })]);
  await atomicJson(requestPath, safeTask);
  return requestPath;
}

export async function waitForDiscoveryResult(root: string, task: DiscoveryTask, budget: DiscoveryBudgetProfile, isCancelled: () => Promise<boolean>): Promise<DiscoveryResult> {
  const resultPath = path.join(root, "results", task.tool_run_id, "result.json");
  const cancelPath = path.join(root, "cancel", task.tool_run_id);
  const deadline = Date.now() + Math.min(DISCOVERY_WAIT_MS, Math.max(30_000, budget.wall_clock_seconds * 1000 + 20_000));
  while (Date.now() < deadline) {
    if (await isCancelled()) await writeFile(cancelPath, "cancel\n", { mode: 0o660 }).catch(() => undefined);
    try {
      const info = await lstat(resultPath);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024) throw new Error("discovery_result_invalid");
      const parsed = DiscoveryResultSchema.parse(JSON.parse(await readFile(resultPath, "utf8")));
      if (!["completed", "failed", "cancelled"].includes(parsed.status) || (parsed.status === "completed" && parsed.coverage_status === "complete" && parsed.artifacts.length === 0) || parsed.assessment_id !== task.assessment_id || parsed.tool_run_id !== task.tool_run_id || parsed.tool !== task.tool || parsed.scope_policy_sha256 !== task.scope_policy_sha256 || parsed.tool_version !== DISCOVERY_TOOL_VERSIONS[task.tool] || parsed.adapter_version !== DISCOVERY_ADAPTER_VERSION || !parsed.started_at || !parsed.finished_at) throw new Error("discovery_result_invalid");
      const scope = DiscoveryScopeSchema.parse(JSON.parse(await readFile(path.join(root, "scopes", `${task.scope_id}.json`), "utf8")));
      const budgetValue = DiscoveryBudgetProfileSchema.parse(JSON.parse(await readFile(path.join(root, "budgets", `${task.budget_profile_id}.json`), "utf8")));
      if (!verifyDiscoveryScope(scope) || scope.scope_id !== task.scope_id || scope.assessment_id !== task.assessment_id || scope.policy_sha256 !== task.scope_policy_sha256 || budgetValue.profile_id !== task.budget_profile_id) throw new Error("discovery_result_invalid");
      const argv = task.tool === "httpx" ? buildHttpxArgv(task, budgetValue) : buildKatanaArgv(task, scope, budgetValue);
      const proxy = buildPolicyProxyUrl(task);
      const expectedConfig = sha256(JSON.stringify({ tool: task.tool, version: parsed.tool_version, adapter: parsed.adapter_version, argv: argv.map((value) => value === task.seed_url ? "<authorized-seed>" : value === proxy ? "<policy-proxy>" : value), budget: budgetValue }));
      if (parsed.config_sha256 !== expectedConfig) throw new Error("discovery_result_invalid");
      return parsed;
    } catch (error) {
      if (error instanceof Error && error.message === "discovery_result_invalid") throw error;
      if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") throw new Error("discovery_result_invalid");
    }
    await delay(250);
  }
  await writeFile(cancelPath, "cancel\n", { mode: 0o660 }).catch(() => undefined);
  throw new Error("timeout");
}

export async function readGatewayEvents(root: string, toolRunId: string): Promise<{ reason: string | null; denials: number }> {
  const eventsRoot = process.env.DISCOVERY_GATEWAY_EVENTS_DIR ?? path.join(root, "gateway-events");
  const file = path.join(eventsRoot, `${toolRunId}.jsonl`);
  let bytes: Buffer;
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024) throw new Error("gateway_events_invalid");
    bytes = await readFile(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return { reason: null, denials: 0 };
    throw new Error("gateway_events_invalid");
  }
  const lines = bytes.toString("utf8").split(/\r?\n/).filter(Boolean);
  if (lines.length > 256) throw new Error("gateway_events_invalid");
  let reason: string | null = null;
  for (const line of lines) {
    let value: unknown;
    try { value = JSON.parse(line); } catch { throw new Error("gateway_events_invalid"); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("gateway_events_invalid");
    const record = value as Record<string, unknown>;
    if (Object.keys(record).sort().join(",") !== "reason_code,timestamp" || typeof record.timestamp !== "string" || !Number.isFinite(Date.parse(record.timestamp)) || typeof record.reason_code !== "string" || !isReasonCode(record.reason_code) || !EVENT_REASONS.has(record.reason_code)) throw new Error("gateway_events_invalid");
    reason ??= record.reason_code;
  }
  return { reason, denials: lines.length };
}

export async function verifyDiscoveryArtifact(root: string, result: DiscoveryResult, descriptor: DiscoveryResult["artifacts"][number]): Promise<Buffer> {
  const expectedKind = result.tool === "httpx" ? "httpx_json" : "katana_json";
  if (descriptor.artifact_kind !== expectedKind || descriptor.byte_size > DISCOVERY_ARTIFACT_LIMIT || !/^[0-9a-f]{64}$/.test(descriptor.sha256)) throw new Error("artifact_metadata_invalid");
  const source = path.resolve(root, "results", result.tool_run_id, discoveryArtifactLeaf(result.tool));
  const rootPath = path.resolve(root);
  if (!inside(rootPath, source)) throw new Error("artifact_path_invalid");
  const info = await lstat(source);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== descriptor.byte_size || info.size > DISCOVERY_ARTIFACT_LIMIT) throw new Error("artifact_metadata_invalid");
  const [realRoot, realSource] = await Promise.all([realpath(rootPath), realpath(source)]);
  if (!inside(realRoot, realSource)) throw new Error("artifact_path_invalid");
  const bytes = await readFile(source);
  if (sha256(bytes) !== descriptor.sha256) throw new Error("artifact_hash_mismatch");
  return bytes;
}
