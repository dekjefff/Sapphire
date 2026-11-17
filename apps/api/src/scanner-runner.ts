import { createHash, randomUUID } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { cp, lstat, mkdir, readFile, readdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const workDir = process.env.SCAN_WORK_DIR ?? "/scan-work";
const configDir = process.env.SCANNER_CONFIG_DIR ?? "/app/scanner-config";
const semgrepVersion = "1.185.0";
const trivyVersion = "0.76.2";
const adapterVersion = "1.0.0";
const maxTaskBytes = 64 * 1024;
const maxArtifactBytes = 100 * 1024 * 1024;
const maxDiagnosticBytes = 1024 * 1024;
const timeoutMs = 10 * 60 * 1000;
const graceMs = 5_000;
const excludedDirectories = ["node_modules", ".next", "dist", "build", "vendor", "coverage", "out", ".turbo", ".cache", "target", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".gradle", ".git"];

type ToolName = "semgrep" | "trivy";
type Task = { task_id: string; assessment_id: string; tool_run_id: string; intake_job_id: string; source_type: "local_path" | "zip"; source_path: string; tool: ToolName };
type Output = { artifact_kind: string; media_type: string; relative_path: string; sha256: string; byte_size: number; exit_code: number | null; duration_ms: number; status: "complete" | "failed" | "cancelled"; failure_code: string | null; stderr_bytes: number };
type TrivyDbProvenance = { metadata_sha256: string; version: number; next_update: string | null; updated_at: string | null; downloaded_at: string | null };

const maxTrivyMetadataBytes = 16 * 1024;
const trivyTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

function isUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function contained(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function parseTask(value: unknown): Task | null {
  if (!value || typeof value !== "object") return null;
  const task = value as Record<string, unknown>;
  if (!isUuid(task.task_id) || !isUuid(task.assessment_id) || !isUuid(task.tool_run_id) || !isUuid(task.intake_job_id)) return null;
  if (task.source_type !== "local_path" && task.source_type !== "zip") return null;
  if (task.tool !== "semgrep" && task.tool !== "trivy") return null;
  if (typeof task.source_path !== "string" || !isAbsolute(task.source_path)) return null;
  return task as Task;
}

async function validateSourcePath(task: Task): Promise<string> {
  const path = await import("node:fs/promises").then(({ realpath }) => realpath(task.source_path));
  const root = task.source_type === "local_path" ? (process.env.WORKSPACE_ROOTS ?? "/workspace").split(":")[0] : (process.env.INTAKE_DIR ?? "/intake");
  const canonicalRoot = await import("node:fs/promises").then(({ realpath }) => realpath(root));
  if (!contained(canonicalRoot, path)) throw new Error("source_outside_allowed_root");
  if (task.source_type === "zip") {
    const workRoot = (process.env.INTAKE_DIR ?? "/intake");
    const rel = relative(await import("node:fs/promises").then(({ realpath }) => realpath(workRoot)), path).split(sep);
    if (rel[0] === "" || !rel[0].startsWith(`work-${task.intake_job_id}-`)) throw new Error("invalid_zip_snapshot");
  }
  const info = await stat(path);
  if (!info.isDirectory()) throw new Error("source_not_directory");
  return path;
}

async function readTrivyDbProvenance(): Promise<TrivyDbProvenance> {
  const dbRoot = "/tmp/trivy-cache/db";
  const metadataPath = join(dbRoot, "metadata.json");
  const dbInfo = await lstat(dbRoot).catch(() => null);
  const metadataInfo = await lstat(metadataPath).catch(() => null);
  if (!dbInfo?.isDirectory() || dbInfo.isSymbolicLink() || !metadataInfo?.isFile() || metadataInfo.isSymbolicLink()) throw new Error("trivy_db_metadata_missing");
  if (metadataInfo.size <= 0 || metadataInfo.size > maxTrivyMetadataBytes) throw new Error("trivy_db_metadata_invalid");
  const bytes = await readFile(metadataPath);
  if (bytes.length !== metadataInfo.size || bytes.length > maxTrivyMetadataBytes) throw new Error("trivy_db_metadata_invalid");
  let parsed: Record<string, unknown>;
  try {
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_metadata");
    parsed = value as Record<string, unknown>;
  } catch { throw new Error("trivy_db_metadata_invalid"); }
  const version = parsed.Version;
  if (!Number.isSafeInteger(version) || Number(version) < 1 || Number(version) > 100) throw new Error("trivy_db_metadata_invalid");
  const timestamp = (value: unknown): string | null => typeof value === "string" && value.length <= 40 && trivyTimestamp.test(value) && Number.isFinite(Date.parse(value)) ? value : null;
  return {
    metadata_sha256: createHash("sha256").update(bytes).digest("hex"),
    version: Number(version),
    next_update: timestamp(parsed.NextUpdate),
    updated_at: timestamp(parsed.UpdatedAt),
    downloaded_at: timestamp(parsed.DownloadedAt),
  };
}

async function killProcessTree(child: ChildProcess, signal: NodeJS.Signals): Promise<void> {
  if (!child.pid) return;
  try { process.kill(-child.pid, signal); }
  catch { try { child.kill(signal); } catch { /* already exited */ } }
}

async function runCommand(binary: string, args: string[], outputPath: string, artifactKind: string, taskId: string, durationLimitMs = timeoutMs): Promise<Output> {
  const started = Date.now();
  const bytes: Buffer[] = [];
  let outputBytes = 0;
  let stderrBytes = 0;
  let failureCode: string | null = null;
  const cancelPath = join(workDir, "cancel", `${taskId}.cancel`);
  const child = spawn(binary, args, {
    cwd: "/app",
    env: {
      PATH: "/usr/local/bin:/usr/bin:/bin:/opt/semgrep/bin",
      HOME: "/tmp",
      TMPDIR: "/tmp",
      SEMGREP_SEND_METRICS: "off",
      SEMGREP_ENABLE_VERSION_CHECK: "0",
      TRIVY_DISABLE_TELEMETRY: "true",
      TRIVY_CACHE_DIR: "/tmp/trivy-cache",
    },
    shell: false,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let forceTimer: NodeJS.Timeout | undefined;
  const kill = async (code: string) => {
    if (failureCode) return;
    failureCode = code;
    await killProcessTree(child, "SIGTERM");
    forceTimer = setTimeout(() => { void killProcessTree(child, "SIGKILL"); }, graceMs);
  };
  const timeout = setTimeout(() => { void kill("timeout"); }, durationLimitMs);
  const cancelPoll = setInterval(() => {
    void import("node:fs/promises").then(({ access }) => access(cancelPath)).then(() => kill("cancelled")).catch(() => undefined);
  }, 500);
  child.stdout.on("data", (chunk: Buffer) => {
    outputBytes += chunk.length;
    if (outputBytes <= maxArtifactBytes) bytes.push(Buffer.from(chunk));
    else void kill("artifact_limit_exceeded");
  });
  child.stderr.on("data", (chunk: Buffer) => { stderrBytes = Math.min(maxDiagnosticBytes, stderrBytes + chunk.length); });

  let exitCode: number | null = null;
  try {
    exitCode = await new Promise<number | null>((resolveExit, reject) => {
      child.once("error", reject);
      child.once("close", (code) => resolveExit(code));
    });
  } catch { failureCode = failureCode ?? "scanner_unavailable"; }
  finally { clearTimeout(timeout); clearInterval(cancelPoll); if (forceTimer) clearTimeout(forceTimer); }

  const data = Buffer.concat(bytes);
  const fs = await import("node:fs/promises");
  await fs.writeFile(outputPath, data, { mode: 0o600 });
  const status = failureCode === "cancelled" ? "cancelled" : failureCode || exitCode !== 0 ? "failed" : "complete";
  return { artifact_kind: artifactKind, media_type: outputPath.endsWith(".sarif") ? "application/sarif+json" : "application/json", relative_path: relative(workDir, outputPath).split(sep).join("/"), sha256: createHash("sha256").update(data).digest("hex"), byte_size: data.length, exit_code: exitCode, duration_ms: Date.now() - started, status, failure_code: failureCode ?? (exitCode === 0 ? null : "scanner_exit_nonzero"), stderr_bytes: stderrBytes };
}

async function makeSemgrepArgs(format: "json" | "sarif", source: string): Promise<string[]> {
  const args = ["scan", "--config", join(configDir, "semgrep.yml"), `--${format}`, "--metrics=off", "--disable-version-check", "--no-git-ignore", "--timeout", "10"];
  for (const directory of excludedDirectories) args.push("--exclude", `**/${directory}/**`);
  args.push(source);
  return args;
}

function makeTrivyArgs(source: string): string[] {
  const args = ["--config", join(configDir, "trivy-config.yml"), "fs", "--format", "json", "--exit-code", "0", "--scanners", "vuln,secret", "--cache-dir", "/tmp/trivy-cache", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-version-check", "--disable-telemetry", "--timeout", "10m"];
  for (const directory of excludedDirectories) args.push("--skip-dirs", `**/${directory}`);
  args.push(source);
  return args;
}

async function scan(task: Task): Promise<void> {
  const source = await validateSourcePath(task);
  const outputDir = join(workDir, "results", task.task_id);
  await mkdir(outputDir, { recursive: true, mode: 0o777 });
  const toolVersion = task.tool === "semgrep" ? semgrepVersion : trivyVersion;
  const configPath = task.tool === "semgrep" ? join(configDir, "semgrep.yml") : join(configDir, "trivy-config.yml");
  const configBytes = await readFile(configPath);
  const configSha256 = createHash("sha256").update(configBytes).update(JSON.stringify({ excludedDirectories, semgrepFormats: ["json", "sarif"], trivyScanners: ["vuln", "secret"], adapterVersion })).digest("hex");
  const artifacts: Output[] = [];
  let trivyDbProvenance: TrivyDbProvenance | null = null;
  let failureCode: string | null = null;
  if (task.tool === "semgrep") {
    const semgrepDeadline = Date.now() + timeoutMs;
    for (const format of ["json", "sarif"] as const) {
      const kind = format === "json" ? "semgrep_json" : "semgrep_sarif";
      const file = join(outputDir, `semgrep.${format}`);
      const remaining = Math.max(1, semgrepDeadline - Date.now());
      artifacts.push(await runCommand("/opt/semgrep/bin/semgrep", await makeSemgrepArgs(format, source), file, kind, task.task_id, remaining));
      if (artifacts[artifacts.length - 1].status === "cancelled") break;
      if (Date.now() >= semgrepDeadline) break;
    }
  } else {
    try { trivyDbProvenance = await readTrivyDbProvenance(); }
    catch (error) { failureCode = error instanceof Error && ["trivy_db_metadata_missing", "trivy_db_metadata_invalid"].includes(error.message) ? error.message : "trivy_db_metadata_invalid"; }
    if (!failureCode) artifacts.push(await runCommand("/usr/local/bin/trivy", makeTrivyArgs(source), join(outputDir, "trivy.json"), "trivy_json", task.task_id));
  }
  const failed = Boolean(failureCode) || artifacts.some((artifact) => artifact.status !== "complete");
  const result = {
    task_id: task.task_id,
    assessment_id: task.assessment_id,
    tool_run_id: task.tool_run_id,
    tool: task.tool,
    status: artifacts.some((artifact) => artifact.status === "cancelled") ? "cancelled" : failed ? "failed" : "complete",
    failure_code: failureCode ?? artifacts.find((artifact) => artifact.failure_code)?.failure_code ?? null,
    tool_version: toolVersion,
    adapter_version: adapterVersion,
    config_id: task.tool === "semgrep" ? "sapphire-semgrep-local-v1" : "sapphire-trivy-offline-v1",
    config_sha256: configSha256,
    provenance: task.tool === "trivy" ? { trivy_db: trivyDbProvenance } : {},
    artifacts,
  };
  const tmp = join(workDir, "results", `${task.task_id}.tmp`);
  const final = join(workDir, "results", `${task.task_id}.result.json`);
  await writeFile(tmp, JSON.stringify(result), { mode: 0o666 });
  await rename(tmp, final);
}

async function processTask(file: string): Promise<void> {
  const taskId = basename(file, ".json");
  if (!isUuid(taskId)) { await rm(file, { force: true }); return; }
  const claimed = join(workDir, "processing", `${taskId}.json`);
  try { await rename(file, claimed); } catch { return; }
  let task: Task | null = null;
  try {
    const taskInfo = await lstat(claimed);
    if (!taskInfo.isFile() || taskInfo.isSymbolicLink()) throw new Error("invalid_task_type");
    const info = await stat(claimed);
    if (info.size > maxTaskBytes) throw new Error("invalid_task_size");
    task = parseTask(JSON.parse(await readFile(claimed, "utf8")));
    if (!task || task.task_id !== taskId) throw new Error("invalid_task");
    await scan(task);
  } catch (error) {
    const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "runner_failure";
    const failure = { task_id: taskId, assessment_id: task?.assessment_id ?? null, tool_run_id: task?.tool_run_id ?? null, tool: task?.tool ?? null, status: "failed", failure_code: code, tool_version: task?.tool === "semgrep" ? semgrepVersion : task?.tool === "trivy" ? trivyVersion : null, adapter_version: adapterVersion, config_id: task?.tool === "semgrep" ? "sapphire-semgrep-local-v1" : task?.tool === "trivy" ? "sapphire-trivy-offline-v1" : null, config_sha256: null, provenance: task?.tool === "trivy" ? { trivy_db: null } : {}, artifacts: [] };
    const tmp = join(workDir, "results", `${taskId}.tmp`);
    await writeFile(tmp, JSON.stringify(failure), { mode: 0o666 });
    await rename(tmp, join(workDir, "results", `${taskId}.result.json`));
  } finally { await rm(claimed, { force: true }).catch(() => undefined); }
}

async function main(): Promise<void> {
  await Promise.all(["requests", "processing", "results", "cancel"].map((name) => mkdir(join(workDir, name), { recursive: true })));
  await mkdir("/tmp/trivy-cache", { recursive: true });
  await cp("/trivy-db/db", "/tmp/trivy-cache/db", { recursive: true, force: true, errorOnExist: false }).catch(() => undefined);
  const config = await readFile(join(configDir, "trivy-config.yml"));
  if (config.length > maxTaskBytes) throw new Error("invalid_config");
  console.log("Sapphire isolated scanner runner is ready");
  while (true) {
    const entries = await readdir(join(workDir, "requests")).catch(() => []);
    for (const entry of entries) if (entry.endsWith(".json")) await processTask(join(workDir, "requests", entry));
    await delay(500);
  }
}

main().catch((error) => { console.error("Scanner runner failed to start:", error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "configuration_error"); process.exit(1); });
