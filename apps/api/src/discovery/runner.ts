import { createHash, randomUUID } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { chmod, copyFile, lstat, mkdir, readFile, readdir, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import {
  DiscoveryBudgetProfileSchema, DiscoveryResultSchema, DiscoveryScopeSchema, DiscoveryTaskSchema,
  type DiscoveryBudgetProfile, type DiscoveryResult, type DiscoveryScope, type DiscoveryTask,
} from "../discovery-contracts.js";
import { assertUrlInDiscoveryScope, verifyDiscoveryScope } from "../discovery-scope-policy.js";
import { ADAPTER_VERSION, DISCOVERY_GATEWAY_URL, HTTPX_VERSION, KATANA_VERSION, buildHttpxArgv, buildKatanaArgv, buildPolicyProxyUrl } from "./adapters.js";
import { parseHttpxJsonl, parseKatanaJsonl, type SanitizedObservation } from "./parsers.js";

const ROOT = "/discovery-work";
const GATEWAY = DISCOVERY_GATEWAY_URL;
const VERSIONS = { httpx: HTTPX_VERSION, katana: KATANA_VERSION } as const;
const OUTPUT_LIMIT = 8 * 1024 * 1024;
const INPUT_LIMIT = 64 * 1024;
let stopping = false;
let child: ChildProcess | undefined;

for (const signal of ["SIGTERM", "SIGINT"] as const) process.once(signal, () => {
  stopping = true;
  child?.kill("SIGKILL");
});

function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }
function uuid(value: string): boolean { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
function assertSafeGateway(): void {
  const configured = process.env.DISCOVERY_GATEWAY_URL;
  if (configured !== GATEWAY) throw new Error("Required discovery gateway configuration is missing or unsafe");
}

async function readJson<T>(file: string, maxBytes: number, schema: { parse(value: unknown): T }): Promise<T> {
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size > maxBytes) throw new Error("Invalid bounded discovery input file");
  const value: unknown = JSON.parse(await readFile(file, "utf8"));
  return schema.parse(value);
}

async function atomicJson(file: string, value: unknown): Promise<void> {
  const temp = `${file}.${randomUUID()}.tmp`;
  await writeFile(temp, `${JSON.stringify(value)}\n`, { flag: "wx", mode: 0o660 });
  await rename(temp, file);
}

function toolPath(tool: DiscoveryTask["tool"]): string { return `/usr/local/bin/${tool}`; }

async function verifyBinary(tool: DiscoveryTask["tool"]): Promise<void> {
  const version = await invoke(toolPath(tool), ["-version"], 10_000, 1024);
  const text = Buffer.concat([version.stdout, version.stderr]).toString("utf8");
  if (version.code !== 0 || !text.includes(VERSIONS[tool])) throw new Error("Pinned discovery binary version check failed");
}

type ProcessResult = { code: number | null; stdout: Buffer; stderr: Buffer; timedOut: boolean; cancelled: boolean; oversized: boolean };
function invoke(binary: string, argv: string[], timeoutMs: number, outputMax: number, cancelFile?: string, proxy: string = GATEWAY): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const proc = spawn(binary, argv, {
      shell: false, stdio: ["ignore", "pipe", "pipe"],
      env: {
        PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/tmp", TMPDIR: "/tmp",
        HTTP_PROXY: proxy, HTTPS_PROXY: proxy, http_proxy: proxy, https_proxy: proxy,
        NO_PROXY: "", no_proxy: "",
      },
    });
    child = proc;
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0, timedOut = false, cancelled = false, oversized = false, settled = false;
    const collect = (list: Buffer[]) => (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > outputMax) { oversized = true; proc.kill("SIGKILL"); return; }
      list.push(chunk);
    };
    proc.stdout.on("data", collect(stdout)); proc.stderr.on("data", collect(stderr));
    const timer = setTimeout(() => { timedOut = true; proc.kill("SIGKILL"); }, timeoutMs);
    const cancelCheck = setInterval(async () => {
      if (stopping || (cancelFile && await fileExists(cancelFile))) { cancelled = true; proc.kill("SIGKILL"); }
    }, 200);
    const finish = (code: number | null) => {
      if (settled) return; settled = true; clearTimeout(timer); clearInterval(cancelCheck); child = undefined;
      resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), timedOut, cancelled, oversized });
    };
    proc.once("error", () => finish(null)); proc.once("close", (code) => finish(code));
  });
}

async function fileExists(file: string): Promise<boolean> {
  try { const s = await stat(file); return s.isFile(); } catch { return false; }
}

function sanitizedLines(rows: SanitizedObservation[]): Buffer {
  return Buffer.from(rows.map((row) => JSON.stringify(row)).join("\n") + (rows.length ? "\n" : ""), "utf8");
}

async function verifyHttpxOrigin(task: DiscoveryTask, scope: DiscoveryScope): Promise<boolean> {
  const marker = path.join(ROOT, "verified-origins", task.assessment_id, `${scope.policy_sha256}.json`);
  try {
    const value = JSON.parse(await readFile(marker, "utf8")) as Record<string, unknown>;
    return value.assessment_id === task.assessment_id && value.scope_id === scope.scope_id
      && value.scope_policy_sha256 === scope.policy_sha256 && value.status === "completed"
      && typeof value.httpx_tool_run_id === "string" && uuid(value.httpx_tool_run_id)
      && value.httpx_version === VERSIONS.httpx;
  } catch { return false; }
}

async function processRequest(requestFile: string): Promise<void> {
  const base = path.basename(requestFile, ".json");
  if (!uuid(base)) { await rm(requestFile, { force: true }); return; }
  const processingFile = path.join(ROOT, "processing", `${base}.json`);
  // The gateway independently reads requests/<tool_run_id>.json to authenticate every proxy
  // request, so keep that immutable file present until the child process has exited.
  try { await copyFile(requestFile, processingFile, 1); } catch { return; }
  let task: DiscoveryTask | undefined;
  let scope: DiscoveryScope | undefined;
  const started = new Date().toISOString();
  let failure: DiscoveryResult["failure_reason_code"] = null;
  let status: DiscoveryResult["status"] = "completed";
  let coverage: DiscoveryResult["coverage_status"] = "complete";
  let rows: SanitizedObservation[] = [];
  let redirects = 0, policyDenials = 0, responseBytes = 0;
  let rawArtifact: Buffer | undefined;
  let binaryVersion = "unknown";
  let configHash = sha256("discovery-config-unavailable");
  const artifacts: DiscoveryResult["artifacts"] = [];
  try {
    task = await readJson(processingFile, INPUT_LIMIT, DiscoveryTaskSchema);
    if (task.tool_run_id !== base) throw new Error("Tool-run ID does not match the queue request filename");
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(task.budget_profile_id) || task.budget_profile_id.includes("..")) {
      throw new Error("Invalid budget profile identifier");
    }
    scope = await readJson(path.join(ROOT, "scopes", `${task.scope_id}.json`), INPUT_LIMIT, DiscoveryScopeSchema);
    const budget = await readJson(path.join(ROOT, "budgets", `${task.budget_profile_id}.json`), INPUT_LIMIT, DiscoveryBudgetProfileSchema);
    if (!verifyDiscoveryScope(scope) || scope.scope_id !== task.scope_id || scope.assessment_id !== task.assessment_id
      || scope.policy_sha256 !== task.scope_policy_sha256) throw new Error("Discovery scope verification failed");
    if (budget.profile_id !== task.budget_profile_id) throw new Error("Discovery budget reference mismatch");
    const seed = assertUrlInDiscoveryScope(task.seed_url, scope);
    if (seed.search || seed.hash) throw new Error("Seed URL must not contain query or fragment data");
    if (!uuid(task.tool_run_id) || !uuid(task.assessment_id) || !uuid(task.scope_id)) throw new Error("Invalid discovery identifiers");
    if (task.cancellation_ref !== task.tool_run_id) throw new Error("Invalid cancellation reference");
    assertSafeGateway();
    if (task.tool === "katana" && !(await verifyHttpxOrigin(task, scope))) {
      failure = "scope_invalid"; status = "failed"; coverage = "incomplete";
      throw new Error("An HTTPX origin verification marker is required before Katana");
    }
    const cancelFile = path.join(ROOT, "cancel", task.tool_run_id);
    if (await fileExists(cancelFile)) { failure = "cancelled"; status = "cancelled"; coverage = "incomplete"; throw new Error("Discovery cancelled before start"); }
    await verifyBinary(task.tool);
    binaryVersion = VERSIONS[task.tool];
    const argv = task.tool === "httpx" ? buildHttpxArgv(task, budget) : buildKatanaArgv(task, scope, budget);
    const requestProxy = buildPolicyProxyUrl(task);
    configHash = sha256(JSON.stringify({ tool: task.tool, version: binaryVersion, adapter: ADAPTER_VERSION, argv: argv.map((v) => v === task!.seed_url ? "<authorized-seed>" : v === requestProxy ? "<policy-proxy>" : v), budget }));
    const result = await invoke(toolPath(task.tool), argv, budget.wall_clock_seconds * 1000, OUTPUT_LIMIT, cancelFile, requestProxy);
    if (result.cancelled) { failure = "cancelled"; status = "cancelled"; coverage = "incomplete"; }
    else if (result.timedOut) { failure = "timeout"; status = "failed"; coverage = "incomplete"; }
    else if (result.oversized) { failure = "byte_budget_exhausted"; status = "failed"; coverage = "incomplete"; }
    else if (result.code !== 0) { failure = "tool_failed"; status = "failed"; coverage = "incomplete"; }
    else {
      const text = result.stdout.toString("utf8");
      rows = task.tool === "httpx" ? parseHttpxJsonl(text, scope) : parseKatanaJsonl(text, scope);
      redirects = rows.filter((r) => r.redirect_observed).length;
      responseBytes = rows.reduce((sum, r) => sum + (r.content_length ?? 0), 0);
      if (rows.length >= budget.unique_urls) { rows = rows.slice(0, budget.unique_urls); failure = "url_budget_exhausted"; coverage = "incomplete"; }
      if (redirects > 0 && !failure) { failure = "redirect_denied"; coverage = "incomplete"; }
      rawArtifact = sanitizedLines(rows);
      if (task.tool === "httpx" && rows.some((r) => r.url === seed.origin + seed.pathname && r.status_code !== null && r.status_code < 400)) {
        const markerDir = path.join(ROOT, "verified-origins", task.assessment_id);
        await mkdir(markerDir, { recursive: true, mode: 0o2770 });
        await chmod(markerDir, 0o2770);
        await atomicJson(path.join(markerDir, `${scope.policy_sha256}.json`), {
          assessment_id: task.assessment_id, scope_id: scope.scope_id, scope_policy_sha256: scope.policy_sha256,
          httpx_tool_run_id: task.tool_run_id, httpx_version: binaryVersion, config_sha256: configHash,
          status: "completed", verified_at: new Date().toISOString(),
        });
      }
    }
  } catch (error) {
    if (!failure) {
      failure = error instanceof SyntaxError ? "malformed_tool_output" : "scope_invalid";
      status = "failed"; coverage = "incomplete";
    }
    // Error details may contain hostile input or paths. Never persist them.
  }
  if (!task) { await rm(processingFile, { force: true }); await rm(requestFile, { force: true }); return; }
  if (rawArtifact) {
    const artifactFile = path.join(ROOT, "results", task.tool_run_id, task.tool === "httpx" ? "httpx.jsonl" : "katana.jsonl");
    await mkdir(path.dirname(artifactFile), { recursive: true, mode: 0o2770 });
    await chmod(path.dirname(artifactFile), 0o2770);
    await writeFile(artifactFile, rawArtifact, { mode: 0o660 });
    artifacts.push({ artifact_id: randomUUID(), artifact_kind: task.tool === "httpx" ? "httpx_json" : "katana_json", sha256: sha256(rawArtifact), byte_size: rawArtifact.length });
  }
  const result = DiscoveryResultSchema.parse({
    schema_version: 1, assessment_id: task.assessment_id, tool_run_id: task.tool_run_id, tool: task.tool,
    tool_version: binaryVersion, adapter_version: ADAPTER_VERSION, config_sha256: configHash,
    scope_policy_sha256: task.scope_policy_sha256, status, coverage_status: coverage,
    failure_reason_code: failure, counters: {
      urls_seen: rows.length, requests_sent: rows.length, responses_received: rows.filter((r) => r.status_code !== null).length,
      response_bytes: responseBytes, endpoints_persisted: rows.length, redirects_denied: redirects, policy_denials: policyDenials,
    }, started_at: started, finished_at: new Date().toISOString(), artifacts,
  });
  const resultFile = path.join(ROOT, "results", task.tool_run_id, "result.json");
  await mkdir(path.dirname(resultFile), { recursive: true, mode: 0o2770 });
  await chmod(path.dirname(resultFile), 0o2770);
  await atomicJson(resultFile, result);
  await rm(processingFile, { force: true });
  await rm(requestFile, { force: true });
}

async function recoverProcessing(): Promise<void> {
  const dir = path.join(ROOT, "processing");
  for (const name of await readdir(dir).catch(() => [])) {
    if (!/^[0-9a-f-]{36}\.json$/i.test(name)) continue;
    try { await rm(path.join(dir, name), { force: true }); } catch { /* next queue scan handles recovery */ }
  }
}

async function main(): Promise<void> {
  if (process.env.DISCOVERY_WORK_DIR && process.env.DISCOVERY_WORK_DIR !== ROOT) throw new Error("Unsafe discovery work directory configuration");
  assertSafeGateway();
  for (const subdir of ["requests", "processing", "scopes", "budgets", "results", "cancel", "verified-origins"]) {
    const dir = path.join(ROOT, subdir);
    await mkdir(dir, { recursive: true, mode: 0o2770 });
    await chmod(dir, 0o2770);
  }
  await recoverProcessing();
  while (!stopping) {
    const requestDir = path.join(ROOT, "requests");
    const names = (await readdir(requestDir)).filter((name) => /^[0-9a-f-]{36}\.json$/i.test(name)).sort();
    if (names.length) await processRequest(path.join(requestDir, names[0]!));
    else await delay(200);
  }
}

main().catch(() => { process.exitCode = 1; });
