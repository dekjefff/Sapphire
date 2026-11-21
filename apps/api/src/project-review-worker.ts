import { rm } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { pool } from "./db.js";
import { groqReview } from "./groq-review.js";
import { inspectSource } from "./intake.js";
import {
  projectLifetimeBudget, projectReviewBudget, reviewProjectSource, reviewSliceStops,
  type ProjectReviewReport, type ScannerReport,
} from "./project-review.js";
import { reviewSnapshot } from "./project-review-queue.js";

type Job = {
  assessment_id: string; source_sha256: string; static_report: ScannerReport;
  consent_at: Date; report: ProjectReviewReport | null;
};
let stopping = false;

async function expireJobs() {
  const closed = await pool.query<{ assessment_id: string }>(`
    UPDATE project_code_reviews r SET
      status=CASE WHEN r.cancel_requested OR a.status='cancelled' THEN 'cancelled' ELSE 'incomplete' END,
      reason=CASE WHEN r.cancel_requested OR a.status='cancelled' THEN 'cancelled'
                  WHEN r.status='queued' THEN 'project_budget'
                  WHEN r.status='running' THEN 'review_worker_interrupted' ELSE 'static_handoff_unavailable' END,
      updated_at=now()
    FROM assessments a WHERE a.id=r.assessment_id AND (
      (r.status='waiting_for_scans' AND (a.status IN ('cancelled','failed','completed') OR r.cancel_requested)) OR
      (r.status='queued' AND (a.status='cancelled' OR r.cancel_requested OR r.consent_at <= now() - interval '48 hours')) OR
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
        AND coalesce((report->>'next_attempt_at')::timestamptz, 'epoch'::timestamptz) <= now()
      ORDER BY updated_at,assessment_id LIMIT 1 FOR UPDATE SKIP LOCKED
    )
    UPDATE project_code_reviews r SET status='running',reason=NULL,updated_at=now()
    FROM next WHERE r.assessment_id=next.assessment_id
    RETURNING r.assessment_id,r.source_sha256,r.static_report,r.consent_at,r.report
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
  let keepSnapshot = false;
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
    const projectDeadline = job.consent_at.getTime() + projectLifetimeBudget.durationMs;
    const budget = {
      requests: Math.min(projectReviewBudget.requests, projectLifetimeBudget.requests - (job.report?.requests ?? 0)),
      estimatedTokens: Math.min(projectReviewBudget.estimatedTokens, projectLifetimeBudget.estimatedTokens - (job.report?.estimated_tokens_reserved ?? 0)),
      durationMs: Math.min(projectReviewBudget.durationMs, projectDeadline - Date.now()),
    };
    if (budget.requests <= 0 || budget.estimatedTokens <= 0 || budget.durationMs <= 0) {
      reason = "project_budget";
      throw new Error(reason);
    }
    const report = await reviewProjectSource({ root: source.scanRoot, files: source.files, staticReport: job.static_report }, groqReview(key), {
      cancelled: () => cancelled(id),
      budget,
      previous: job.report,
      async checkpoint(progress) {
        await pool.query("UPDATE project_code_reviews SET report=$2,updated_at=now() WHERE assessment_id=$1 AND status='running'", [id, progress]);
      },
      async recordFailure(failure) {
        await pool.query(
          "INSERT INTO audit_events (assessment_id,actor,event_type,details) VALUES ($1,'project-reviewer','ai_code_review.attempt_failed',$2)",
          [id, failure],
        );
      },
    });
    const stopped = await cancelled(id);
    const limitReached = report.reason !== null && reviewSliceStops.has(report.reason);
    const next = Math.max(Date.now() + 60_000, Date.parse(report.next_attempt_at ?? "") || 0);
    const continuing = !stopped && limitReached && next < projectDeadline &&
      report.requests < projectLifetimeBudget.requests &&
      report.estimated_tokens_reserved + 7600 <= projectLifetimeBudget.estimatedTokens;
    const providerHold = report.reason === "model_rate_limited" || Boolean(report.next_attempt_at);
    const finalReason = stopped ? "cancelled" : continuing ? providerHold ? "waiting_for_provider" : "continuing_review" :
      limitReached ? "project_budget" : report.reason;
    if (continuing) report.next_attempt_at = new Date(next).toISOString();
    else delete report.next_attempt_at;
    const saved = await pool.query(`
      UPDATE project_code_reviews SET status=$2,report=$3,reason=$4,updated_at=now()
      WHERE assessment_id=$1 AND status='running'
    `, [id, stopped ? "cancelled" : continuing ? "queued" : report.reason ? "incomplete" : "completed", report, finalReason]);
    keepSnapshot = continuing && saved.rowCount === 1;
  } catch {
    await pool.query("UPDATE project_code_reviews SET status=$2,reason=$3,updated_at=now() WHERE assessment_id=$1 AND status='running'", [id, reason === "cancelled" ? "cancelled" : "incomplete", reason]);
  } finally {
    if (temp) await rm(temp, { recursive: true, force: true }).catch(() => undefined);
    if (!keepSnapshot) await rm(snapshot, { force: true }).catch(() => undefined);
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
