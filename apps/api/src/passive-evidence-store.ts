import type { Pool } from "pg";
import type { PassiveEvidenceRecord, PassiveEvidenceStore } from "./passive-evidence-api.js";

export function createPassiveEvidenceStore(pool: Pool): PassiveEvidenceStore {
  return {
    async put(assessmentId, evidence) {
      const result = await pool.query(
        `INSERT INTO passive_capture_evidence AS saved (assessment_id, run_id, evidence)
         SELECT id, $2, $3::jsonb FROM assessments WHERE id = $1 FOR KEY SHARE
         ON CONFLICT (assessment_id, run_id) DO UPDATE
         SET evidence = EXCLUDED.evidence WHERE saved.evidence = EXCLUDED.evidence
         RETURNING run_id`,
        [assessmentId, evidence.run_id, JSON.stringify(evidence)],
      );
      if (result.rowCount) return "saved";
      const assessment = await pool.query("SELECT 1 FROM assessments WHERE id = $1", [assessmentId]);
      return assessment.rowCount ? "conflict" : "missing";
    },
    async get(assessmentId, runId) {
      const result = await pool.query<{ evidence: PassiveEvidenceRecord }>(
        "SELECT evidence FROM passive_capture_evidence WHERE assessment_id = $1 AND run_id = $2",
        [assessmentId, runId],
      );
      return result.rows[0]?.evidence ?? null;
    },
    async latest(assessmentId) {
      const result = await pool.query<{ evidence: PassiveEvidenceRecord }>(
        `SELECT evidence FROM passive_capture_evidence WHERE assessment_id = $1
         ORDER BY imported_at DESC, run_id DESC LIMIT 1`,
        [assessmentId],
      );
      return result.rows[0]?.evidence ?? null;
    },
  };
}
