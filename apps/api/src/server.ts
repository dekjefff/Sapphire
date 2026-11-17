import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { createClient } from "redis";
import { pool } from "./db.js";
import { isUuid, QUEUE_NAME, type JobMessage } from "./types.js";
import multipart from "@fastify/multipart";
import { inspectSource, stageUpload, validateLocalPath } from "./intake.js";
import { createAssessmentSchema, createZipAssessmentSchema, validateTarget } from "./validation.js";

const app = Fastify({ logger: true });
const redis = createClient({ url: process.env.REDIS_URL ?? "redis://redis:6379/0" });
redis.on("error", (error) => app.log.error({ err: error }, "Redis client error"));
const artifactDir = process.env.ARTIFACT_DIR ?? "/artifacts";
const origins = (process.env.CORS_ORIGINS ?? "http://localhost:3000").split(",").map((v) => v.trim()).filter(Boolean);
await app.register(cors, { origin: origins, methods: ["GET", "POST"], allowedHeaders: ["Content-Type"] });
await app.register(multipart, { limits: { files: 1, fileSize: 100 * 1024 * 1024, fields: 2, parts: 3 } });

function parseId(value: string): string | null {
  return isUuid(value) ? value : null;
}

async function auditIntakeRejection(sourceType: "local_path" | "zip", reasonCode: string): Promise<void> {
  await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES (NULL, NULL, 'api', 'intake.rejected', $1)", [{ source_type: sourceType, reason_code: reasonCode }]);
}

app.get("/health", async (_request, reply) => {
  let postgres = "unavailable";
  let redisStatus = "unavailable";
  try { await pool.query("SELECT 1"); postgres = "ok"; } catch { /* report degraded health */ }
  try { await redis.ping(); redisStatus = "ok"; } catch { /* report degraded health */ }
  const services = { api: "ok", postgres, redis: redisStatus };
  const healthy = postgres === "ok" && redisStatus === "ok";
  return reply.code(healthy ? 200 : 503).send({ status: healthy ? "ok" : "degraded", services });
});

async function createIntake(projectName: string, repositoryPath: string, sourceType: "local_path" | "zip", sourcePath: string, targetUrl: string, request: import("fastify").FastifyRequest, reply: import("fastify").FastifyReply) {
  const projectId = randomUUID();
  const assessmentId = randomUUID();
  const jobId = randomUUID();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO projects (id, name, repository_path, source_type, source_location, intake_status) VALUES ($1, $2, $3, $4, $5, 'queued')", [projectId, projectName, repositoryPath, sourceType, repositoryPath]);
    await client.query("INSERT INTO assessments (id, project_id, target_url, status) VALUES ($1, $2, $3, 'queued')", [assessmentId, projectId, targetUrl]);
    await client.query("INSERT INTO tool_runs (id, assessment_id, tool_definition_id, status) VALUES ($1, $2, 'source-intake', 'queued')", [jobId, assessmentId]);
    await client.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'intake.requested', $3)", [assessmentId, jobId, { source_type: sourceType }]);
    await client.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'intake.accepted', $3)", [assessmentId, jobId, { source_type: sourceType }]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    if (sourceType === "zip") await rm(sourcePath, { force: true }).catch(() => undefined);
    request.log.error({ err: error }, "Could not persist assessment intake");
    return reply.code(503).send({ detail: "Could not persist assessment intake" });
  } finally { client.release(); }

  const message: JobMessage = { job_id: jobId, assessment_id: assessmentId, source_type: sourceType, source_path: sourcePath };
  try { await redis.rPush(QUEUE_NAME, JSON.stringify(message)); }
  catch (error) {
    if (sourceType === "zip") await rm(sourcePath, { force: true }).catch(() => undefined);
    await pool.query("UPDATE tool_runs SET status='failed', finished_at=now(), error='Queue unavailable' WHERE id=$1", [jobId]);
    await pool.query("UPDATE assessments SET status='failed', updated_at=now() WHERE id=$1", [assessmentId]);
    await pool.query("UPDATE projects SET intake_status='failed' WHERE id=$1", [projectId]);
    await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'intake.failed', $3)", [assessmentId, jobId, { reason: "queue unavailable" }]);
    request.log.error({ err: error }, "Queue unavailable");
    return reply.code(503).send({ detail: "Assessment saved but the queue is unavailable" });
  }
  return reply.code(202).send({ assessment_id: assessmentId, job_id: jobId, status: "queued" });
}

app.post<{ Body: unknown }>("/assessments", async (request, reply) => {
  const parsed = createAssessmentSchema.safeParse(request.body);
  if (!parsed.success) { await auditIntakeRejection("local_path", "invalid_input").catch(() => undefined); return reply.code(422).send({ detail: "Invalid assessment input", issues: parsed.error.issues }); }
  let targetUrl: string;
  try { targetUrl = validateTarget(parsed.data.target_url); }
  catch { await auditIntakeRejection("local_path", "invalid_target").catch(() => undefined); return reply.code(422).send({ detail: "Invalid target" }); }
  let canonicalPath: string;
  try { canonicalPath = await validateLocalPath(parsed.data.repository_path); }
  catch { await auditIntakeRejection("local_path", "source_path_rejected").catch(() => undefined); return reply.code(422).send({ detail: "Repository path is unavailable or outside configured workspace roots" }); }
  return createIntake(parsed.data.project_name, canonicalPath, "local_path", canonicalPath, targetUrl, request, reply);
});

app.post("/assessments/zip", async (request, reply) => {
  const fields: Record<string, string> = {};
  let staged = "";
  let invalidFileField = false;
  const uploadId = randomUUID();
  const stagedPath = join(process.env.INTAKE_DIR ?? "/intake", `${uploadId}.zip`);
  try {
    for await (const part of request.parts()) {
      if (part.type === "file") {
        if (part.fieldname !== "source") {
          invalidFileField = true;
          for await (const _chunk of part.file) { /* drain rejected multipart file */ }
        } else staged = await stageUpload(part.file, uploadId);
      } else fields[part.fieldname] = String(part.value);
    }
  } catch {
    await rm(stagedPath, { force: true }).catch(() => undefined);
    await auditIntakeRejection("zip", "multipart_rejected").catch(() => undefined);
    return reply.code(422).send({ detail: "Invalid or oversized multipart upload" });
  }
  if (invalidFileField) { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "invalid_file_field").catch(() => undefined); return reply.code(422).send({ detail: "ZIP must be uploaded in the source field" }); }
  if (!staged) { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "zip_missing").catch(() => undefined); return reply.code(422).send({ detail: "A ZIP source file is required" }); }
  const parsed = createZipAssessmentSchema.safeParse(fields);
  if (!parsed.success) { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "invalid_input").catch(() => undefined); return reply.code(422).send({ detail: "Invalid assessment input", issues: parsed.error.issues }); }
  let targetUrl: string;
  try { targetUrl = validateTarget(parsed.data.target_url); }
  catch { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "invalid_target").catch(() => undefined); return reply.code(422).send({ detail: "Invalid target" }); }
  return createIntake(parsed.data.project_name, "ZIP upload", "zip", staged, targetUrl, request, reply);
});

app.get("/assessments", async () => {
  const result = await pool.query("SELECT a.id,p.name AS project_name,p.repository_path,p.source_type,p.source_identity_type,p.source_identity,p.intake_status,a.target_url,a.status,a.coverage_status,a.created_at,(SELECT count(*) FROM discovered_routes r WHERE r.assessment_id=a.id)::int AS route_count,(SELECT COALESCE(jsonb_agg(x.route),'[]'::jsonb) FROM (SELECT jsonb_build_object('method',r.method,'path',r.path,'source_file',r.source_file,'source_line',r.source_line,'confidence',r.confidence) AS route FROM discovered_routes r WHERE r.assessment_id=a.id ORDER BY r.source_file,r.source_line NULLS LAST LIMIT 100) x) AS routes,(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',t.name,'category',t.category,'confidence',t.confidence,'evidence',t.evidence,'reason',t.reason) ORDER BY t.category,t.name),'[]'::jsonb) FROM detected_technologies t WHERE t.assessment_id=a.id) AS technologies,(SELECT COALESCE(jsonb_agg(jsonb_build_object('severity',f.severity,'code',f.code,'message',f.message) ORDER BY f.id),'[]'::jsonb) FROM intake_findings f WHERE f.assessment_id=a.id) AS findings,(SELECT count(*)::int FROM normalized_findings nf WHERE nf.assessment_id=a.id) AS normalized_finding_count,(SELECT COALESCE(jsonb_object_agg(severity,finding_count),'{}'::jsonb) FROM (SELECT severity,count(*)::int AS finding_count FROM normalized_findings nf WHERE nf.assessment_id=a.id GROUP BY severity) sev) AS severity_counts FROM assessments a JOIN projects p ON p.id=a.project_id ORDER BY a.created_at DESC LIMIT 100");
  return result.rows.map((row) => ({ ...row, id: String(row.id), created_at: row.created_at.toISOString() }));
});

app.get<{ Params: { assessment_id: string } }>("/assessments/:assessment_id", async (request, reply) => {
  const id = parseId(request.params.assessment_id);
  if (!id) return reply.code(400).send({ detail: "Assessment ID is invalid" });
  const result = await pool.query("SELECT a.id,p.name AS project_name,p.repository_path,p.source_type,p.source_location,p.source_identity_type,p.source_identity,p.source_file_count,p.source_total_bytes,p.intake_status,a.target_url,a.status,a.coverage_status,a.created_at FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1", [id]);
  if (!result.rowCount) return reply.code(404).send({ detail: "Assessment not found" });
  const [jobs, technologies, routes, findings, artifacts, groups] = await Promise.all([
    pool.query("SELECT id,tool_definition_id AS tool,status,coverage_status,tool_version,adapter_version,config_id,config_sha256,exit_code,error,provenance,started_at,finished_at,cancel_requested FROM tool_runs WHERE assessment_id=$1 ORDER BY created_at", [id]),
    pool.query("SELECT name, category, confidence, evidence, reason FROM detected_technologies WHERE assessment_id=$1 ORDER BY category,name", [id]),
    pool.query("SELECT method, path, source_file, source_line, confidence FROM discovered_routes WHERE assessment_id=$1 ORDER BY source_file,source_line NULLS LAST,method,path", [id]),
    pool.query("SELECT severity, code, message, created_at FROM intake_findings WHERE assessment_id=$1 ORDER BY id", [id]),
    pool.query("SELECT id,tool_run_id,artifact_kind,relative_path,media_type,sha256,byte_size,metadata,created_at FROM scan_artifacts WHERE assessment_id=$1 ORDER BY created_at,artifact_kind", [id]),
    pool.query("SELECT g.id,g.fingerprint,g.title,g.severity,count(f.id)::int AS duplicate_count,COALESCE(jsonb_agg(jsonb_build_object('id',f.id,'tool_run_id',f.tool_run_id,'artifact_id',f.artifact_id,'raw_pointer',f.raw_pointer,'finding_type',f.finding_type,'rule_id',f.rule_id,'cve_id',f.cve_id,'title',f.title,'message',f.message,'severity',f.severity,'confidence',f.confidence,'source_file',f.source_file,'start_line',f.start_line,'start_column',f.start_column,'end_line',f.end_line,'end_column',f.end_column,'evidence',f.evidence) ORDER BY f.created_at,f.id) FILTER (WHERE f.id IS NOT NULL),'[]'::jsonb) AS findings FROM finding_groups g LEFT JOIN normalized_findings f ON f.group_id=g.id WHERE g.assessment_id=$1 GROUP BY g.id ORDER BY CASE g.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,g.title LIMIT 500", [id]),
  ]);
  const row = result.rows[0];
  return { ...row,id:String(row.id),created_at:row.created_at.toISOString(),job:jobs.rows.map((job)=>({...job,id:String(job.id),started_at:job.started_at?.toISOString()??null,finished_at:job.finished_at?.toISOString()??null})),technologies:technologies.rows,routes:routes.rows,findings:findings.rows,artifacts:artifacts.rows.map((artifact)=>({...artifact,id:String(artifact.id),tool_run_id:String(artifact.tool_run_id),created_at:artifact.created_at.toISOString()})),finding_groups:groups.rows };
});

app.get<{ Params: { artifact_id: string } }>("/artifacts/:artifact_id", async (request, reply) => {
  const id = parseId(request.params.artifact_id);
  if (!id) return reply.code(400).send({ detail: "Artifact ID is invalid" });
  const result = await pool.query("SELECT relative_path,media_type,sha256 FROM scan_artifacts WHERE id=$1", [id]);
  if (!result.rowCount) return reply.code(404).send({ detail: "Artifact not found" });
  const artifactPath = resolve(artifactDir, result.rows[0].relative_path);
  if (!artifactPath.startsWith(`${resolve(artifactDir)}${process.platform === "win32" ? "\\" : "/"}`)) return reply.code(404).send({ detail: "Artifact not found" });
  return reply.type(result.rows[0].media_type).header("X-Content-SHA256", result.rows[0].sha256).send(createReadStream(artifactPath));
});

app.get<{ Params: { job_id: string } }>("/jobs/:job_id", async (request, reply) => {
  const id = parseId(request.params.job_id);
  if (!id) return reply.code(400).send({ detail: "Job ID is invalid" });
  const result = await pool.query("SELECT id,assessment_id,status,started_at,finished_at,error,cancel_requested,coverage_status,tool_version,adapter_version,config_id,config_sha256,exit_code FROM tool_runs WHERE id=$1", [id]);
  if (!result.rowCount) return reply.code(404).send({ detail: "Job not found" });
  const row = result.rows[0];
  return { ...row, id: String(row.id), assessment_id: String(row.assessment_id), started_at: row.started_at?.toISOString() ?? null, finished_at: row.finished_at?.toISOString() ?? null };
});

app.post<{ Params: { job_id: string } }>("/jobs/:job_id/cancel", async (request, reply) => {
  const id = parseId(request.params.job_id);
  if (!id) return reply.code(400).send({ detail: "Job ID is invalid" });
  const selected = await pool.query("SELECT assessment_id FROM tool_runs WHERE id=$1", [id]);
  if (!selected.rowCount) return reply.code(404).send({ detail: "Job not found" });
  const assessmentId = String(selected.rows[0].assessment_id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query("UPDATE tool_runs SET cancel_requested=true WHERE assessment_id=$1 AND status IN ('queued','running') AND cancel_requested=false RETURNING id,status", [assessmentId]);
    if (!result.rowCount) { await client.query("ROLLBACK"); return reply.code(409).send({ detail: "Assessment has no cancellable runs" }); }
    for (const row of result.rows) await client.query("INSERT INTO audit_events (assessment_id,tool_run_id,actor,event_type,details) VALUES ($1,$2,'api','job.cancel_requested',$3)", [assessmentId, row.id, { requested_via: id }]);
    await client.query("COMMIT");
    return { id, assessment_id: assessmentId, cancel_requested: true, runs_cancelled: result.rows.map((row) => ({ id: String(row.id), status: row.status })) };
  } catch (error) { await client.query("ROLLBACK"); request.log.error({ err: error }, "Could not request assessment cancellation"); return reply.code(503).send({ detail: "Could not request cancellation" }); }
  finally { client.release(); }
});

async function start(): Promise<void> {
  await mkdir(artifactDir, { recursive: true });
  await redis.connect();
  await app.listen({ host: "0.0.0.0", port: Number(process.env.PORT ?? 8000) });
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => { void app.close().finally(async () => { if (redis.isOpen) await redis.quit(); await pool.end(); process.exit(0); }); });
}
start().catch((error) => { app.log.error(error); process.exit(1); });
