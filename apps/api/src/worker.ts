import { createHash, randomUUID } from "node:crypto";
import { access, copyFile, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { PoolClient } from "pg";
import { createClient } from "redis";
import { pool } from "./db.js";
import { inspectSource, type IntakeResult } from "./intake.js";
import { parseSemgrepJson, parseTrivyJson, type NormalizedFinding } from "./normalize.js";
import { isUuid, QUEUE_NAME, type JobMessage } from "./types.js";

const redis = createClient({ url: process.env.REDIS_URL ?? "redis://redis:6379/0" });
redis.on("error", (error) => console.error("Redis worker error:", error));
const artifactDir = process.env.ARTIFACT_DIR ?? "/artifacts";
const scanWorkDir = process.env.SCAN_WORK_DIR ?? "/scan-work";
const semgrepVersion = "1.185.0";
const trivyVersion = "0.76.2";
const adapterVersion = "1.0.0";
const runnerWaitMs = 12 * 60 * 1000;
let stopping = false;

type RunnerArtifact = { artifact_kind: "semgrep_json" | "semgrep_sarif" | "trivy_json"; media_type: string; relative_path: string; sha256: string; byte_size: number; exit_code: number | null; duration_ms: number; status: "complete" | "failed" | "cancelled"; failure_code: string | null; stderr_bytes: number };
type RunnerResult = { task_id: string; assessment_id: string; tool_run_id: string; tool: "semgrep" | "trivy"; status: "complete" | "failed" | "cancelled"; failure_code: string | null; tool_version: string; adapter_version: string; config_id: string; config_sha256: string | null; provenance?: Record<string, unknown>; artifacts: RunnerArtifact[] };

function inside(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

async function audit(assessmentId: string, jobId: string | null, actor: string, event: string, details: object): Promise<void> {
  await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1,$2,$3,$4,$5)", [assessmentId, jobId, actor, event, details]);
}

function safeIntakePersistReason(error: unknown): string {
  if (error instanceof Error && /^[a-z0-9_]+$/.test(error.message)) return error.message;
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && /^[0-9A-Z]{5}$/.test(code)) return `intake_persist_${code.toLowerCase()}`;
  }
  return "intake_persist_failed";
}

async function pollCancellation(toolRunId: string): Promise<boolean> {
  const result = await pool.query("SELECT cancel_requested FROM tool_runs WHERE id=$1", [toolRunId]);
  return Boolean(result.rows[0]?.cancel_requested);
}

async function enqueueAndWait(task: { task_id: string; assessment_id: string; tool_run_id: string; intake_job_id: string; source_type: "local_path" | "zip"; source_path: string; tool: "semgrep" | "trivy" }): Promise<RunnerResult> {
  const requestDir = join(scanWorkDir, "requests");
  const resultDir = join(scanWorkDir, "results");
  const cancelDir = join(scanWorkDir, "cancel");
  await Promise.all([requestDir, resultDir, cancelDir].map((path) => mkdir(path, { recursive: true })));
  const requestPath = join(requestDir, `${task.task_id}.json`);
  const tempPath = join(requestDir, `${task.task_id}.tmp`);
  const resultPath = join(resultDir, `${task.task_id}.result.json`);
  const cancelPath = join(cancelDir, `${task.task_id}.cancel`);
  await rm(resultPath, { force: true });
  await rm(cancelPath, { force: true });
  await writeFile(tempPath, JSON.stringify(task), { mode: 0o644, flag: "wx" });
  await rename(tempPath, requestPath);
  const deadline = Date.now() + runnerWaitMs;
  let cancelRequested = false;
  while (Date.now() < deadline) {
    if (await access(resultPath).then(() => true).catch(() => false)) {
      const info = await stat(resultPath);
      if (info.size > 64 * 1024) throw new Error("runner_result_too_large");
      const result = JSON.parse(await readFile(resultPath, "utf8")) as RunnerResult;
      if (result.task_id !== task.task_id || result.assessment_id !== task.assessment_id || result.tool_run_id !== task.tool_run_id || result.tool !== task.tool || !["complete", "failed", "cancelled"].includes(result.status) || !Array.isArray(result.artifacts)) throw new Error("runner_result_invalid");
      return result;
    }
    if (!cancelRequested && await pollCancellation(task.tool_run_id)) {
      cancelRequested = true;
      await writeFile(cancelPath, "cancel", { mode: 0o644 }).catch(() => undefined);
    }
    await delay(500);
  }
  await writeFile(cancelPath, "cancel", { mode: 0o644 }).catch(() => undefined);
  throw new Error("scanner_runner_timeout");
}

function artifactLeaf(kind: RunnerArtifact["artifact_kind"]): string {
  if (kind === "semgrep_json") return "semgrep.json";
  if (kind === "semgrep_sarif") return "semgrep.sarif";
  return "trivy.json";
}

async function saveArtifact(assessmentId: string, toolRunId: string, result: RunnerResult, item: RunnerArtifact, client: PoolClient): Promise<string> {
  const workRoot = resolve(scanWorkDir);
  const rawPath = resolve(scanWorkDir, item.relative_path);
  if (!inside(workRoot, rawPath) || item.byte_size < 0 || item.byte_size > 100 * 1024 * 1024 || !/^[0-9a-f]{64}$/.test(item.sha256)) throw new Error("artifact_metadata_invalid");
  const bytes = await readFile(rawPath);
  if (bytes.length !== item.byte_size || createHash("sha256").update(bytes).digest("hex") !== item.sha256) throw new Error("artifact_hash_mismatch");
  const relativePath = `scans/${assessmentId}/${toolRunId}/${artifactLeaf(item.artifact_kind)}`;
  const output = resolve(artifactDir, relativePath);
  if (!inside(resolve(artifactDir), output)) throw new Error("artifact_path_invalid");
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, bytes, { mode: 0o600 });
  const metadata = { tool: result.tool, tool_version: result.tool_version, adapter_version: result.adapter_version, config_id: result.config_id, config_sha256: result.config_sha256, provenance: result.provenance ?? {}, exit_code: item.exit_code, duration_ms: item.duration_ms, runner_status: item.status, failure_code: item.failure_code, stderr_bytes: item.stderr_bytes };
  await writeFile(`${output}.meta.json`, JSON.stringify({ artifact_kind: item.artifact_kind, media_type: item.media_type, sha256: item.sha256, byte_size: bytes.length, ...metadata }, null, 2), { mode: 0o600 });
  await client.query("INSERT INTO scan_artifacts (id, assessment_id, tool_run_id, artifact_kind, relative_path, media_type, sha256, byte_size, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", [randomUUID(), assessmentId, toolRunId, item.artifact_kind, relativePath, item.media_type, item.sha256, bytes.length, metadata]);
  return relativePath;
}

async function parseArtifact(item: RunnerArtifact, workDir: string, sourceRoot: string): Promise<NormalizedFinding[]> {
  if (item.artifact_kind === "semgrep_sarif") return [];
  const filePath = resolve(workDir, item.relative_path);
  if (!inside(resolve(workDir), filePath)) throw new Error("artifact_path_invalid");
  const raw = JSON.parse(await readFile(filePath, "utf8")) as unknown;
  return item.artifact_kind === "semgrep_json" ? parseSemgrepJson(raw, sourceRoot) : parseTrivyJson(raw, sourceRoot);
}

async function persistFindings(client: PoolClient, assessmentId: string, toolRunId: string, artifactIdByKind: Map<string, string>, findings: NormalizedFinding[]): Promise<void> {
  if (!findings.length) return;
  const groups = new Map<string, { id: string; assessment_id: string; fingerprint: string; title: string; severity: string }>();
  for (const finding of findings) if (!groups.has(finding.fingerprint)) groups.set(finding.fingerprint, { id: randomUUID(), assessment_id: assessmentId, fingerprint: finding.fingerprint, title: finding.title.slice(0, 1000), severity: finding.severity });
  const groupResult = await client.query("INSERT INTO finding_groups (id, assessment_id, fingerprint, title, severity) SELECT id,assessment_id,fingerprint,title,severity FROM jsonb_to_recordset($1::jsonb) AS x(id uuid,assessment_id uuid,fingerprint text,title text,severity text) ON CONFLICT (assessment_id,fingerprint) DO UPDATE SET title=EXCLUDED.title RETURNING id,fingerprint", [JSON.stringify([...groups.values()])]);
  const groupIds = new Map<string, string>(groupResult.rows.map((row) => [row.fingerprint, String(row.id)]));
  const records = findings.map((finding) => {
    const artifactKind = finding.rawPointer.startsWith("/results/") ? "semgrep_json" : "trivy_json";
    const artifactId = artifactIdByKind.get(artifactKind);
    const groupId = groupIds.get(finding.fingerprint);
    if (!artifactId || !groupId) throw new Error("finding_provenance_missing");
    return { id: randomUUID(), assessment_id: assessmentId, tool_run_id: toolRunId, artifact_id: artifactId, group_id: groupId, raw_pointer: finding.rawPointer, finding_type: finding.findingType, rule_id: finding.ruleId, cve_id: finding.cveId, title: finding.title, message: finding.message, severity: finding.severity, confidence: finding.confidence, source_file: finding.sourceFile, start_line: finding.startLine, start_column: finding.startColumn, end_line: finding.endLine, end_column: finding.endColumn, fingerprint: finding.fingerprint, evidence: finding.evidence };
  });
  for (let offset = 0; offset < records.length; offset += 250) {
    await client.query("INSERT INTO normalized_findings (id,assessment_id,tool_run_id,artifact_id,group_id,raw_pointer,finding_type,rule_id,cve_id,title,message,severity,confidence,source_file,start_line,start_column,end_line,end_column,fingerprint,evidence) SELECT id,assessment_id,tool_run_id,artifact_id,group_id,raw_pointer,finding_type,rule_id,cve_id,title,message,severity,confidence,source_file,start_line,start_column,end_line,end_column,fingerprint,evidence FROM jsonb_to_recordset($1::jsonb) AS x(id uuid,assessment_id uuid,tool_run_id uuid,artifact_id uuid,group_id uuid,raw_pointer text,finding_type text,rule_id text,cve_id text,title text,message text,severity text,confidence numeric,source_file text,start_line integer,start_column integer,end_line integer,end_column integer,fingerprint text,evidence jsonb)", [JSON.stringify(records.slice(offset, offset + 250))]);
  }
}

async function runTool(assessmentId: string, intakeJobId: string, source: IntakeResult, tool: "semgrep" | "trivy", toolRunId: string): Promise<{ status: "completed" | "failed" | "cancelled"; findings: number; failureCode: string | null }> {
  const started = await pool.query("UPDATE tool_runs SET status='running',started_at=now(),coverage_status='pending' WHERE id=$1 AND status='queued' AND cancel_requested=false RETURNING id", [toolRunId]);
  if (!started.rowCount) {
    await pool.query("UPDATE tool_runs SET status='cancelled',finished_at=now(),coverage_status='incomplete',error='cancelled_before_start' WHERE id=$1 AND status='queued' AND cancel_requested=true", [toolRunId]);
    await audit(assessmentId, toolRunId, "worker", "tool.cancelled", { tool, phase: "before_start" });
    return { status: "cancelled", findings: 0, failureCode: "cancelled" };
  }
  await audit(assessmentId, toolRunId, "worker", "tool.started", { tool, network: false, source_read_only: true });
  const taskId = toolRunId;
  let result: RunnerResult;
  try {
    result = await enqueueAndWait({ task_id: taskId, assessment_id: assessmentId, tool_run_id: toolRunId, intake_job_id: intakeJobId, source_type: source.sourceType as "local_path" | "zip", source_path: source.scanRoot, tool });
  } catch (error) {
    const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "scanner_runner_failure";
    await pool.query("UPDATE tool_runs SET status='failed',finished_at=now(),error=$2,tool_version=$3,adapter_version=$4,coverage_status='incomplete' WHERE id=$1", [toolRunId, code, tool === "semgrep" ? semgrepVersion : trivyVersion, adapterVersion]);
    await audit(assessmentId, toolRunId, "worker", "tool.failed", { tool, reason_code: code });
    return { status: "failed", findings: 0, failureCode: code };
  }

  const client = await pool.connect();
  let normalized: NormalizedFinding[] = [];
  let parseError: string | null = null;
  let failureCode = result.failure_code;
  const artifactIds = new Map<string, string>();
  try {
    await client.query("BEGIN");
    for (const artifact of result.artifacts) {
      const relativePath = await saveArtifact(assessmentId, toolRunId, result, artifact, client);
      const saved = await client.query("SELECT id FROM scan_artifacts WHERE tool_run_id=$1 AND artifact_kind=$2", [toolRunId, artifact.artifact_kind]);
      if (saved.rowCount) artifactIds.set(artifact.artifact_kind, String(saved.rows[0].id));
      if (artifact.artifact_kind !== "semgrep_sarif") {
        try { normalized.push(...await parseArtifact(artifact, scanWorkDir, source.scanRoot)); }
        catch (error) { parseError = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "scanner_json_invalid"; }
      }
      void relativePath;
    }
    if (normalized.length > 20_000) { normalized = normalized.slice(0, 20_000); parseError = "finding_limit_exceeded"; }
    if (parseError && !failureCode) failureCode = parseError;
    if (normalized.length && artifactIds.size) await persistFindings(client, assessmentId, toolRunId, artifactIds, normalized);
    const cancelled = result.status === "cancelled";
    const complete = result.status === "complete" && !failureCode && !parseError && (tool === "semgrep" ? artifactIds.has("semgrep_json") && artifactIds.has("semgrep_sarif") : artifactIds.has("trivy_json"));
    const status = cancelled ? "cancelled" : complete ? "completed" : "failed";
    const coverage = complete ? "complete" : "incomplete";
    const exitCode = result.artifacts.find((item) => item.exit_code !== null)?.exit_code ?? null;
    await client.query("UPDATE tool_runs SET status=$2,finished_at=now(),error=$3,tool_version=$4,adapter_version=$5,config_id=$6,config_sha256=$7,exit_code=$8,coverage_status=$9,provenance=$10 WHERE id=$1", [toolRunId, status, complete ? null : failureCode ?? "scanner_incomplete", result.tool_version, result.adapter_version, result.config_id, result.config_sha256, exitCode, coverage, JSON.stringify(result.provenance ?? {})]);
    await client.query("INSERT INTO audit_events (assessment_id,tool_run_id,actor,event_type,details) VALUES ($1,$2,'worker',$3,$4)", [assessmentId, toolRunId, cancelled ? "tool.cancelled" : complete ? "tool.completed" : "tool.failed", { tool, reason_code: complete || cancelled ? null : failureCode ?? "scanner_incomplete", artifact_count: result.artifacts.length, finding_count: normalized.length, exit_code: exitCode }]);
    await client.query("COMMIT");
    return { status, findings: normalized.length, failureCode: complete || cancelled ? null : failureCode ?? "scanner_incomplete" };
  } catch (error) {
    await client.query("ROLLBACK");
    const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "finding_persist_failed";
    await pool.query("UPDATE tool_runs SET status='failed',finished_at=now(),error=$2,tool_version=$3,adapter_version=$4,config_id=$5,config_sha256=$6,coverage_status='incomplete',provenance=$7 WHERE id=$1", [toolRunId, code, result.tool_version, result.adapter_version, result.config_id, result.config_sha256, JSON.stringify(result.provenance ?? {})]);
    await audit(assessmentId, toolRunId, "worker", "tool.failed", { tool, reason_code: code });
    return { status: "failed", findings: 0, failureCode: code };
  } finally {
    client.release();
    await rm(join(scanWorkDir, "requests", `${taskId}.json`), { force: true }).catch(() => undefined);
    await rm(join(scanWorkDir, "cancel", `${taskId}.cancel`), { force: true }).catch(() => undefined);
    await rm(join(scanWorkDir, "results", taskId), { recursive: true, force: true }).catch(() => undefined);
    await rm(join(scanWorkDir, "results", `${taskId}.result.json`), { force: true }).catch(() => undefined);
  }
}

async function recordIntakeFailure(assessmentId: string, jobId: string, reason: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("UPDATE tool_runs SET status='failed',finished_at=now(),error=$2,coverage_status='incomplete' WHERE id=$1", [jobId, reason]);
    await client.query("UPDATE assessments SET status='failed',coverage_status='incomplete',updated_at=now() WHERE id=$1", [assessmentId]);
    await client.query("UPDATE projects SET intake_status='failed' WHERE id=(SELECT project_id FROM assessments WHERE id=$1)", [assessmentId]);
    await client.query("INSERT INTO intake_findings (assessment_id,severity,code,message) VALUES ($1,'error','intake_failed',$2)", [assessmentId, reason]);
    await client.query("INSERT INTO audit_events (assessment_id,tool_run_id,actor,event_type,details) VALUES ($1,$2,'worker','intake.failed',$3)", [assessmentId, jobId, { reason_code: reason }]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
}

async function processJob(raw: string): Promise<void> {
  let message: JobMessage;
  try { message = JSON.parse(raw) as JobMessage; }
  catch { console.error("Discarded malformed queue message"); return; }
  if (!message || typeof message !== "object" || !isUuid(message.job_id) || !isUuid(message.assessment_id) || !["local_path", "zip"].includes(message.source_type) || typeof message.source_path !== "string") { console.error("Discarded invalid queue message"); return; }
  const { job_id: jobId, assessment_id: assessmentId } = message;
  const started = await pool.query("UPDATE tool_runs SET status='running',started_at=now() WHERE id=$1 AND assessment_id=$2 AND status='queued' AND cancel_requested=false RETURNING id", [jobId, assessmentId]);
  if (!started.rowCount) {
    const cancelled = await pool.query("UPDATE tool_runs SET status='cancelled',finished_at=now(),coverage_status='incomplete' WHERE id=$1 AND assessment_id=$2 AND status='queued' AND cancel_requested=true RETURNING id", [jobId, assessmentId]);
    if (cancelled.rowCount) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("UPDATE assessments SET status='cancelled',coverage_status='incomplete',updated_at=now() WHERE id=$1", [assessmentId]);
        await client.query("UPDATE projects SET intake_status='cancelled' WHERE id=(SELECT project_id FROM assessments WHERE id=$1)", [assessmentId]);
        await client.query("INSERT INTO audit_events (assessment_id,tool_run_id,actor,event_type,details) VALUES ($1,$2,'worker','intake.cancelled',$3)", [assessmentId, jobId, { phase: "before_start" }]);
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      finally { client.release(); }
    }
    return;
  }
  await pool.query("UPDATE assessments SET status='running',coverage_status='pending',updated_at=now() WHERE id=$1", [assessmentId]);
  await pool.query("UPDATE projects SET intake_status='running' WHERE id=(SELECT project_id FROM assessments WHERE id=$1)", [assessmentId]);
  await audit(assessmentId, jobId, "worker", "intake.started", { source_type: message.source_type, executes_commands: false });

  let source: IntakeResult;
  try { source = await inspectSource({ type: message.source_type, path: message.source_path }, jobId); }
  catch (error) {
    const reason = error instanceof Error && /^(Repository exceeds|ZIP exceeds|Unsafe ZIP|Invalid ZIP|ZIP entry|Symbolic links|Special files|File exceeds|Repository path|Target)/.test(error.message) ? "source_rejected" : "intake_failed";
    await recordIntakeFailure(assessmentId, jobId, reason);
    if (message.source_type === "zip") await rm(message.source_path, { force: true }).catch(() => undefined);
    return;
  }

  const semgrepRunId = randomUUID();
  const trivyRunId = randomUUID();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const project = await client.query("SELECT project_id FROM assessments WHERE id=$1", [assessmentId]);
    const projectId = project.rows[0]?.project_id;
    if (!projectId) throw new Error("assessment_project_missing");
    const intakeRun = await client.query("SELECT cancel_requested,status FROM tool_runs WHERE id=$1 FOR UPDATE", [jobId]);
    if (!intakeRun.rowCount || intakeRun.rows[0].status !== "running") throw new Error("intake_run_not_running");
    if (intakeRun.rows[0].cancel_requested) {
      await client.query("UPDATE tool_runs SET status='cancelled',finished_at=now(),coverage_status='incomplete' WHERE id=$1", [jobId]);
      await client.query("UPDATE assessments SET status='cancelled',coverage_status='incomplete',updated_at=now() WHERE id=$1", [assessmentId]);
      await client.query("UPDATE projects SET intake_status='cancelled' WHERE id=$1", [projectId]);
      await client.query("INSERT INTO audit_events (assessment_id,tool_run_id,actor,event_type,details) VALUES ($1,$2,'worker','intake.cancelled',$3)", [assessmentId, jobId, { phase: "after_inspection", results_discarded: true }]);
      await client.query("COMMIT");
      if (source.temporaryRoot) await rm(source.temporaryRoot, { recursive: true, force: true }).catch(() => undefined);
      if (message.source_type === "zip") await rm(message.source_path, { force: true }).catch(() => undefined);
      return;
    }
    await client.query("UPDATE projects SET source_location=$2,source_identity_type=$3,source_identity=$4,source_file_count=$5,source_total_bytes=$6,intake_status='completed' WHERE id=$1", [projectId, source.canonicalLocation, source.identityType, source.identity, source.fileCount, source.totalBytes]);
    for (const tech of source.technologies) await client.query("INSERT INTO detected_technologies (assessment_id,name,category,confidence,evidence,reason) VALUES ($1,$2,$3,$4,$5,$6)", [assessmentId, tech.name, tech.category, tech.confidence, JSON.stringify(tech.evidence), tech.reason]);
    for (const route of source.routes) await client.query("INSERT INTO discovered_routes (assessment_id,method,path,source_file,source_line,confidence) VALUES ($1,$2,$3,$4,$5,$6)", [assessmentId, route.method, route.path, route.file, route.line, route.confidence]);
    for (const finding of source.findings) await client.query("INSERT INTO intake_findings (assessment_id,severity,code,message) VALUES ($1,$2,$3,$4)", [assessmentId, finding.severity, finding.code, finding.message]);
    await client.query("UPDATE tool_runs SET status='completed',finished_at=now(),coverage_status='complete' WHERE id=$1", [jobId]);
    await client.query("INSERT INTO tool_runs (id,assessment_id,tool_definition_id,status) VALUES ($1,$3,'semgrep','queued'),($2,$3,'trivy','queued')", [semgrepRunId, trivyRunId, assessmentId]);
    await client.query("INSERT INTO audit_events (assessment_id,tool_run_id,actor,event_type,details) VALUES ($1,$2,'worker','intake.completed',$3)", [assessmentId, jobId, { identity_type: source.identityType, file_count: source.fileCount, technology_count: source.technologies.length, route_count: source.routes.length, finding_count: source.findings.length }]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    if (source.temporaryRoot) await rm(source.temporaryRoot, { recursive: true, force: true }).catch(() => undefined);
    const reason = safeIntakePersistReason(error);
    await recordIntakeFailure(assessmentId, jobId, reason);
    if (message.source_type === "zip") await rm(message.source_path, { force: true }).catch(() => undefined);
    return;
  } finally { client.release(); }

  try {
    const semgrep = await runTool(assessmentId, jobId, source, "semgrep", semgrepRunId);
    if (semgrep.status === "cancelled") {
      await pool.query("UPDATE tool_runs SET status='cancelled',finished_at=now(),coverage_status='incomplete',error='cancelled_before_start' WHERE id=$1 AND status='queued'", [trivyRunId]);
      await pool.query("INSERT INTO audit_events (assessment_id,tool_run_id,actor,event_type,details) VALUES ($1,$2,'worker','tool.cancelled',$3)", [assessmentId, trivyRunId, { tool: "trivy", phase: "after_semgrep_cancel" }]);
      await pool.query("UPDATE assessments SET status='cancelled',coverage_status='incomplete',updated_at=now() WHERE id=$1", [assessmentId]);
      await audit(assessmentId, null, "worker", "assessment.cancelled", { phase: "static_pipeline" });
      return;
    }
    const trivy = await runTool(assessmentId, jobId, source, "trivy", trivyRunId);
    if (trivy.status === "cancelled") {
      await pool.query("UPDATE assessments SET status='cancelled',coverage_status='incomplete',updated_at=now() WHERE id=$1", [assessmentId]);
      await audit(assessmentId, null, "worker", "assessment.cancelled", { phase: "static_pipeline" });
      return;
    }
    const complete = semgrep.status === "completed" && trivy.status === "completed";
    await pool.query("UPDATE assessments SET status=$2,coverage_status=$3,updated_at=now() WHERE id=$1", [assessmentId, complete ? "completed" : "failed", complete ? "complete" : "incomplete"]);
    await audit(assessmentId, null, "worker", complete ? "assessment.completed" : "assessment.incomplete", { semgrep_status: semgrep.status, trivy_status: trivy.status, finding_count: semgrep.findings + trivy.findings, reason_codes: [semgrep.failureCode, trivy.failureCode].filter(Boolean) });
  } catch (error) {
    const reason = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "pipeline_failure";
    await pool.query("UPDATE assessments SET status='failed',coverage_status='incomplete',updated_at=now() WHERE id=$1", [assessmentId]);
    await audit(assessmentId, null, "worker", "assessment.incomplete", { reason_code: reason });
  } finally {
    if (source.temporaryRoot) await rm(source.temporaryRoot, { recursive: true, force: true }).catch(() => undefined);
    if (message.source_type === "zip") await rm(message.source_path, { force: true }).catch(() => undefined);
  }
}

async function main(): Promise<void> {
  await redis.connect();
  console.log("Sapphire source and static analysis worker is ready");
  while (!stopping) {
    try { const item = await redis.blPop(QUEUE_NAME, 5); if (item) await processJob(item.element); }
    catch (error) { console.error("Worker loop error:", error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "worker_error"); await delay(1500); }
  }
  if (redis.isOpen) await redis.quit();
  await pool.end();
}

for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => { stopping = true; });
main().catch((error) => { console.error("Worker failed to start:", error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "worker_error"); process.exit(1); });
