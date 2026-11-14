import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createClient } from "redis";
import { pool } from "./db.js";
import { isUuid, QUEUE_NAME, type JobMessage } from "./types.js";

const redis = createClient({ url: process.env.REDIS_URL ?? "redis://redis:6379/0" });
redis.on("error", (error) => console.error("Redis worker error:", error));
const artifactDir = process.env.ARTIFACT_DIR ?? "/artifacts";
let stopping = false;

async function audit(assessmentId: string, jobId: string, event: string, details: object): Promise<void> {
  await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'worker', $3, $4)", [assessmentId, jobId, event, details]);
}

async function processJob(raw: string): Promise<void> {
  let message: JobMessage;
  try { message = JSON.parse(raw) as JobMessage; }
  catch { console.error("Discarded malformed queue message"); return; }
  if (!message || typeof message !== "object" || !isUuid(message.job_id) || !isUuid(message.assessment_id)) {
    console.error("Discarded queue message with invalid identifiers");
    return;
  }
  const { job_id: jobId, assessment_id: assessmentId } = message;
  const started = await pool.query("UPDATE tool_runs SET status='running', started_at=now() WHERE id=$1 AND assessment_id=$2 AND status='queued' AND cancel_requested=false RETURNING id", [jobId, assessmentId]);
  if (!started.rowCount) {
    const cancelled = await pool.query("UPDATE tool_runs SET status='cancelled', finished_at=now() WHERE id=$1 AND status='queued' AND cancel_requested=true RETURNING id", [jobId]);
    if (cancelled.rowCount) {
      await pool.query("UPDATE assessments SET status='cancelled', updated_at=now() WHERE id=$1", [assessmentId]);
      await audit(assessmentId, jobId, "job.cancelled", { phase: "before_start" });
    }
    return;
  }
  await pool.query("UPDATE assessments SET status='running', updated_at=now() WHERE id=$1", [assessmentId]);
  await audit(assessmentId, jobId, "job.started", { kind: "dummy" });
  await new Promise((resolve) => setTimeout(resolve, 1000));

  const artifactName = `${jobId}.json`;
  try {
    await mkdir(artifactDir, { recursive: true });
    await writeFile(join(artifactDir, artifactName), JSON.stringify({ job_id: jobId, assessment_id: assessmentId, result: "dummy job completed" }, null, 2), "utf8");
    const completed = await pool.query("UPDATE tool_runs SET status='completed', finished_at=now() WHERE id=$1 AND status='running' AND cancel_requested=false RETURNING id", [jobId]);
    if (completed.rowCount) {
      await pool.query("UPDATE assessments SET status='completed', updated_at=now() WHERE id=$1", [assessmentId]);
      await audit(assessmentId, jobId, "job.completed", { artifact: artifactName });
      return;
    }
    await pool.query("UPDATE tool_runs SET status='cancelled', finished_at=now() WHERE id=$1 AND status='running' AND cancel_requested=true", [jobId]);
    await pool.query("UPDATE assessments SET status='cancelled', updated_at=now() WHERE id=$1", [assessmentId]);
    await audit(assessmentId, jobId, "job.cancelled", { phase: "running" });
  } catch (error) {
    const reason = error instanceof Error ? error.message.slice(0, 500) : "Unknown worker error";
    await pool.query("UPDATE tool_runs SET status='failed', finished_at=now(), error=$2 WHERE id=$1 AND status='running'", [jobId, reason]);
    await pool.query("UPDATE assessments SET status='failed', updated_at=now() WHERE id=$1", [assessmentId]);
    await audit(assessmentId, jobId, "job.failed", { error: reason });
  }
}

async function main(): Promise<void> {
  await redis.connect();
  console.log("Sapphire dummy worker is ready");
  while (!stopping) {
    try {
      const item = await redis.blPop(QUEUE_NAME, 5);
      if (item) await processJob(item.element);
    } catch (error) {
      console.error("Worker loop error:", error);
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
  }
  if (redis.isOpen) await redis.quit();
  await pool.end();
}

for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => { stopping = true; });
main().catch((error) => { console.error(error); process.exit(1); });
