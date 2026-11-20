import { constants } from "node:fs";
import { copyFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { pool } from "./db.js";
import type { ScannerReport } from "./project-review.js";
import { isUuid } from "./types.js";

export function reviewSnapshot(assessmentId: string) {
  if (!isUuid(assessmentId)) throw new Error("invalid_assessment_id");
  return join(process.env.AI_REVIEW_SNAPSHOT_DIR ?? "/ai-review-sources", `${assessmentId}.zip`);
}

export async function queueProjectReview(
  assessmentId: string,
  archive: string,
  sourceSha256: string,
  tools: ScannerReport["tools"],
  intakeGapCodes: string[],
) {
  const requested = await pool.query(
    "SELECT 1 FROM project_code_reviews WHERE assessment_id=$1 AND status='waiting_for_scans' AND NOT cancel_requested",
    [assessmentId],
  );
  if (!requested.rowCount) return;
  const snapshot = reviewSnapshot(assessmentId);
  try {
    const [findings, count] = await Promise.all([
      pool.query<ScannerReport["findings"][number]>(`
        SELECT f.id, r.tool_definition_id AS tool, f.finding_type AS type, left(f.source_file,512) AS file,
               f.start_line AS line, f.severity, left(coalesce(f.cve_id,f.rule_id),100) AS rule
        FROM normalized_findings f JOIN tool_runs r ON r.id=f.tool_run_id
        WHERE f.assessment_id=$1 AND r.tool_definition_id IN ('semgrep','trivy')
        ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,f.id LIMIT 2000
      `, [assessmentId]),
      pool.query<{ total: number }>(`
        SELECT count(*)::int AS total
        FROM normalized_findings f JOIN tool_runs r ON r.id=f.tool_run_id
        WHERE f.assessment_id=$1 AND r.tool_definition_id IN ('semgrep','trivy')
      `, [assessmentId]),
    ]);
    const staticReport: ScannerReport = {
      schema_version: 1, assessment_id: assessmentId, source_sha256: sourceSha256,
      tools, intake_gap_codes: intakeGapCodes, finding_count: count.rows[0].total,
      findings: findings.rows,
    };
    await mkdir(process.env.AI_REVIEW_SNAPSHOT_DIR ?? "/ai-review-sources", { mode: 0o700, recursive: true });
    await copyFile(archive, snapshot, constants.COPYFILE_EXCL);
    const queued = await pool.query(`
      UPDATE project_code_reviews SET status='queued', source_sha256=$2, static_report=$3, updated_at=now()
      WHERE assessment_id=$1 AND status='waiting_for_scans' AND NOT cancel_requested
    `, [assessmentId, sourceSha256, staticReport]);
    if (!queued.rowCount) await rm(snapshot, { force: true });
  } catch {
    // Keep the static pipeline result even when staging the second pass fails.
    await rm(snapshot, { force: true }).catch(() => undefined);
    await pool.query(`
      UPDATE project_code_reviews SET status='incomplete', reason='review_handoff_failed', updated_at=now()
      WHERE assessment_id=$1 AND status='waiting_for_scans'
    `, [assessmentId]);
  }
}
