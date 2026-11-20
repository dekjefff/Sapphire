import { rm } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { pool } from "./db.js";
import { groqReview } from "./groq-review.js";
import { inspectSource } from "./intake.js";
import { reviewProjectSource, type ScannerReport } from "./project-review.js";
import { reviewSnapshot } from "./project-review-queue.js";

type Job = { assessment_id: string; source_sha256: string; static_report: ScannerReport };
let stopping = false;

async function expireJobs() {
  const closed = await pool.query<{ assessment_id: string }>(`
    UPDATE project_code_reviews r SET
      status=CASE WHEN r.cancel_requested OR a.status='cancelled' THEN 'cancelled' ELSE 'incomplete' END,
      reason=CASE WHEN r.cancel_requested OR a.status='cancelled' THEN 'cancelled'
                  WHEN r.status='running' THEN 'review_worker_interrupted' ELSE 'static_handoff_unavailable' END,
      updated_at=now()
    FROM assessments a WHERE a.id=r.assessment_id AND (
      (r.status='waiting_for_scans' AND (a.status IN ('cancelled','failed','completed') OR r.cancel_requested)) OR
      (r.status='queued' AND (a.status='cancelled' OR r.cancel_requested)) OR
      (r.status='running' AND r.updated_at < now() - interval '35 minutes')
    ) RETURNING r.assessment_id
  `);
  for (const { assessment_id: id } of closed.rows) await rm(reviewSnapshot(id), { force: true }).catch(() => undefined);
}

async function claim() {
  const result = await pool.query<Job>(`
    WITH next AS (
      SELECT assessment_id FROM project_code_reviews
      WHERE status='queued' AND NOT cancel_requested
      ORDER BY updated_at,assessment_id LIMIT 1 FOR UPDATE SKIP LOCKED
    )
    UPDATE project_code_reviews r SET status='running',updated_at=now()
    FROM next WHERE r.assessment_id=next.assessment_id
    RETURNING r.assessment_id,r.source_sha256,r.static_report
  `);
  return result.rows[0];
}

async function cancelled(id: string) {
  if (stopping) return true;
  const result = await pool.query<{ allowed: boolean }>(`
    SELECT NOT r.cancel_requested AND r.status='running' AND a.status<>'cancelled' AS allowed
    FROM project_code_reviews r JOIN assessments a ON a.id=r.assessment_id WHERE r.assessment_id=$1
  `, [id]);
  return !result.rows[0]?.allowed;
}

async function processReview(job: Job, key: string | undefined) {
  const id = job.assessment_id;
  const snapshot = reviewSnapshot(id);
  let temp: string | null = null;
  let reason = "review_worker_failed";
  try {
    if (!key) { reason = "model_not_configured"; throw new Error(reason); }
    if (await cancelled(id)) { reason = "cancelled"; throw new Error(reason); }
    reason = "snapshot_unavailable";
    const source = await inspectSource({ type: "zip", path: snapshot }, id);
    temp = source.temporaryRoot;
    reason = "source_digest_mismatch";
    if (source.contentSha256 !== job.source_sha256 || job.static_report.source_sha256 !== job.source_sha256 ||
        job.static_report.assessment_id !== id) throw new Error(reason);
    reason = "review_worker_failed";
    const report = await reviewProjectSource({ root: source.scanRoot, files: source.files, staticReport: job.static_report }, groqReview(key), {
      cancelled: () => cancelled(id),
      async checkpoint(progress) {
        await pool.query("UPDATE project_code_reviews SET report=$2,updated_at=now() WHERE assessment_id=$1 AND status='running'", [id, progress]);
      },
    });
    const stopped = await cancelled(id);
    await pool.query(`
      UPDATE project_code_reviews SET status=$2,report=$3,reason=$4,updated_at=now()
      WHERE assessment_id=$1 AND status='running'
    `, [id, stopped ? "cancelled" : report.reason ? "incomplete" : "completed", report, stopped ? "cancelled" : report.reason]);
  } catch {
    await pool.query("UPDATE project_code_reviews SET status=$2,reason=$3,updated_at=now() WHERE assessment_id=$1 AND status='running'", [id, reason === "cancelled" ? "cancelled" : "incomplete", reason]);
  } finally {
    if (temp) await rm(temp, { recursive: true, force: true }).catch(() => undefined);
    await rm(snapshot, { force: true }).catch(() => undefined);
  }
}

async function main() {
  const key = process.env.GROQ_API_KEY?.trim();
  while (!stopping) {
    try {
      await expireJobs();
      const job = await claim();
      if (job) { await processReview(job, key); continue; }
    } catch {
      console.error("Project source review queue unavailable");
    }
    await delay(2_000);
  }
  await pool.end();
}

for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => { stopping = true; });
main().catch(() => { process.exitCode = 1; });
