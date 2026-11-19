import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { createClient } from "redis";
import { pool } from "./db.js";
import { findNpmCli, registerDashboardCodeReview, runDashboardCodeReview, type SavedCodeReview } from "./dashboard-code-review.js";
import { groqReview } from "./groq-review.js";
import { isUuid, QUEUE_NAME, type JobMessage } from "./types.js";
import { createAssessmentSchema, validateTarget } from "./validation.js";

const app = Fastify({ logger: true });
const redis = createClient({ url: process.env.REDIS_URL ?? "redis://redis:6379/0" });
redis.on("error", (error) => app.log.error({ err: error }, "Redis client error"));
const artifactDir = process.env.ARTIFACT_DIR ?? "/artifacts";
const origins = (process.env.CORS_ORIGINS ?? "http://localhost:3000").split(",").map((v) => v.trim()).filter(Boolean);
await app.register(cors, { origin: origins, methods: ["GET", "POST"], allowedHeaders: ["Content-Type"] });

const groqKey = process.env.GROQ_API_KEY?.trim();
const npmCli = groqKey ? findNpmCli() : undefined;
const dashboardModel = groqKey && npmCli ? groqReview(groqKey) : undefined;
const reviewEvent = "ai_code_review.finished";
registerDashboardCodeReview(app, {
  origins,
  run: dashboardModel && npmCli ? (input) => runDashboardCodeReview(input, dashboardModel, npmCli) : undefined,
  store: {
    async exists(assessmentId) {
      const result = await pool.query("SELECT 1 FROM assessments WHERE id=$1", [assessmentId]);
      return result.rowCount === 1;
    },
    async latest(assessmentId) {
      const result = await pool.query<{ details: SavedCodeReview["report"]; created_at: Date }>(
        "SELECT details, created_at FROM audit_events WHERE assessment_id=$1 AND event_type=$2 ORDER BY id DESC LIMIT 1",
        [assessmentId, reviewEvent],
      );
      const row = result.rows[0];
      return row ? { report: row.details, created_at: row.created_at.toISOString() } : null;
    },
    async save(assessmentId, report) {
      const result = await pool.query<{ created_at: Date }>(
        "INSERT INTO audit_events (assessment_id, actor, event_type, details) VALUES ($1, 'dashboard', $2, $3) RETURNING created_at",
        [assessmentId, reviewEvent, report],
      );
      return { report, created_at: result.rows[0].created_at.toISOString() };
    },
  },
});

function parseId(value: string): string | null {
  return isUuid(value) ? value : null;
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

app.post<{ Body: unknown }>("/assessments", async (request, reply) => {
  const parsed = createAssessmentSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(422).send({ detail: "Invalid assessment input", issues: parsed.error.issues });
  let targetUrl: string;
  try { targetUrl = validateTarget(parsed.data.target_url); }
  catch (error) { return reply.code(422).send({ detail: error instanceof Error ? error.message : "Invalid target" }); }

  const projectId = randomUUID();
  const assessmentId = randomUUID();
  const jobId = randomUUID();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO projects (id, name, repository_path) VALUES ($1, $2, $3)", [projectId, parsed.data.project_name, parsed.data.repository_path]);
    await client.query("INSERT INTO assessments (id, project_id, target_url, status) VALUES ($1, $2, $3, 'queued')", [assessmentId, projectId, targetUrl]);
    await client.query("INSERT INTO tool_runs (id, assessment_id, tool_definition_id, status) VALUES ($1, $2, 'foundation-dummy', 'queued')", [jobId, assessmentId]);
    await client.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'assessment.created', $3)", [assessmentId, jobId, { target_host: new URL(targetUrl).hostname }]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    request.log.error({ err: error }, "Could not persist assessment");
    return reply.code(503).send({ detail: "Could not persist assessment" });
  } finally { client.release(); }

  const message: JobMessage = { job_id: jobId, assessment_id: assessmentId };
  try { await redis.rPush(QUEUE_NAME, JSON.stringify(message)); }
  catch (error) {
    await pool.query("UPDATE tool_runs SET status='failed', finished_at=now(), error='Queue unavailable' WHERE id=$1", [jobId]);
    await pool.query("UPDATE assessments SET status='failed', updated_at=now() WHERE id=$1", [assessmentId]);
    await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'job.enqueue_failed', $3)", [assessmentId, jobId, { reason: "queue unavailable" }]);
    request.log.error({ err: error }, "Queue unavailable");
    return reply.code(503).send({ detail: "Assessment saved but the queue is unavailable" });
  }
  return reply.code(202).send({ assessment_id: assessmentId, job_id: jobId, status: "queued" });
});

app.get("/assessments", async () => {
  const result = await pool.query("SELECT a.id, p.name AS project_name, p.repository_path, a.target_url, a.status, a.created_at FROM assessments a JOIN projects p ON p.id=a.project_id ORDER BY a.created_at DESC LIMIT 100");
  return result.rows.map((row) => ({ ...row, id: String(row.id), created_at: row.created_at.toISOString() }));
});

app.get<{ Params: { assessment_id: string } }>("/assessments/:assessment_id", async (request, reply) => {
  const id = parseId(request.params.assessment_id);
  if (!id) return reply.code(400).send({ detail: "Assessment ID is invalid" });
  const result = await pool.query("SELECT a.id, p.name AS project_name, p.repository_path, a.target_url, a.status, a.created_at FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1", [id]);
  if (!result.rowCount) return reply.code(404).send({ detail: "Assessment not found" });
  const jobs = await pool.query("SELECT id, status, started_at, finished_at, cancel_requested FROM tool_runs WHERE assessment_id=$1 ORDER BY created_at DESC LIMIT 1", [id]);
  const row = result.rows[0];
  const job = jobs.rows[0];
  return { ...row, id: String(row.id), created_at: row.created_at.toISOString(), job: job ? { ...job, id: String(job.id), started_at: job.started_at?.toISOString() ?? null, finished_at: job.finished_at?.toISOString() ?? null } : null };
});

app.get<{ Params: { job_id: string } }>("/jobs/:job_id", async (request, reply) => {
  const id = parseId(request.params.job_id);
  if (!id) return reply.code(400).send({ detail: "Job ID is invalid" });
  const result = await pool.query("SELECT id, assessment_id, status, started_at, finished_at, error, cancel_requested FROM tool_runs WHERE id=$1", [id]);
  if (!result.rowCount) return reply.code(404).send({ detail: "Job not found" });
  const row = result.rows[0];
  return { ...row, id: String(row.id), assessment_id: String(row.assessment_id), started_at: row.started_at?.toISOString() ?? null, finished_at: row.finished_at?.toISOString() ?? null };
});

app.post<{ Params: { job_id: string } }>("/jobs/:job_id/cancel", async (request, reply) => {
  const id = parseId(request.params.job_id);
  if (!id) return reply.code(400).send({ detail: "Job ID is invalid" });
  const result = await pool.query("UPDATE tool_runs SET cancel_requested=true WHERE id=$1 AND status IN ('queued','running') RETURNING id, assessment_id, status", [id]);
  if (!result.rowCount) return reply.code(409).send({ detail: "Job is not cancellable" });
  const row = result.rows[0];
  await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'job.cancel_requested', '{}'::jsonb)", [row.assessment_id, id]);
  return { id: String(row.id), status: row.status, cancel_requested: true };
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
