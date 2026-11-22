import { pool } from "./db.js";

export const activityTimeZone = "Asia/Bangkok";

export async function workspaceOverview(accountId: string) {
  const result = await pool.query(`
    WITH bounds AS (
      SELECT (now() AT TIME ZONE $1)::date AS today
    ), owned_assessments AS (
      SELECT a.id, a.project_id FROM assessments a
      JOIN projects p ON p.id=a.project_id WHERE p.owner_account_id=$2
    ), scan_runs AS (
      SELECT a.project_id, t.status, t.started_at, t.finished_at
      FROM tool_runs t JOIN owned_assessments a ON a.id=t.assessment_id
      WHERE t.tool_definition_id IN ('semgrep','trivy','httpx','katana')
    ), scan_totals AS (
      SELECT count(DISTINCT project_id) FILTER (WHERE finished_at IS NOT NULL) AS projects_scanned,
             count(*) FILTER (WHERE finished_at IS NOT NULL) AS scans,
             coalesce(sum(greatest(0, extract(epoch FROM finished_at-started_at)))
               FILTER (WHERE started_at IS NOT NULL AND finished_at IS NOT NULL), 0) AS scan_seconds
      FROM scan_runs
    ), finding_totals AS (
      SELECT count(*) AS findings, count(*) FILTER (WHERE severity='critical') AS critical,
             count(*) FILTER (WHERE severity='high') AS high
      FROM normalized_findings f JOIN owned_assessments a ON a.id=f.assessment_id
    ), review_totals AS (
      SELECT count(*) AS reviews, count(*) FILTER (WHERE status='completed') AS reviews_completed,
             coalesce(sum((report->>'actual_tokens_reported')::bigint),0) AS tokens,
             coalesce(sum((report->>'requests')::bigint),0) AS ai_requests
      FROM project_code_reviews r JOIN owned_assessments a ON a.id=r.assessment_id
    ), scans_by_day AS (
      SELECT (finished_at AT TIME ZONE $1)::date AS day, count(*) AS scans
      FROM scan_runs CROSS JOIN bounds
      WHERE finished_at >= ((today-364)::timestamp AT TIME ZONE $1)
      GROUP BY 1
    ), tokens_by_day AS (
      SELECT bucket.key::date AS day, sum(bucket.value::bigint) AS tokens
      FROM project_code_reviews r JOIN owned_assessments a ON a.id=r.assessment_id
      CROSS JOIN LATERAL jsonb_each_text(coalesce(r.report->'actual_tokens_by_day','{}'::jsonb)) bucket
      GROUP BY 1
    ), days AS (
      SELECT (today-offsets.n)::date AS day
      FROM bounds CROSS JOIN generate_series(0,364) offsets(n)
    )
    SELECT jsonb_build_object(
      'projects_scanned',scan_totals.projects_scanned,
      'scans',scan_totals.scans,
      'scan_seconds',scan_totals.scan_seconds,
      'assessments',(SELECT count(*) FROM owned_assessments),
      'findings',finding_totals.findings,
      'critical',finding_totals.critical,
      'high',finding_totals.high,
      'reviews',review_totals.reviews,
      'reviews_completed',review_totals.reviews_completed,
      'tokens',review_totals.tokens,
      'ai_requests',review_totals.ai_requests,
      'tokens_without_day',greatest(0,review_totals.tokens-coalesce((SELECT sum(tokens) FROM tokens_by_day),0))
    ) AS totals,
    (SELECT jsonb_agg(
       jsonb_build_object('date',days.day,'scans',coalesce(s.scans,0),'tokens',coalesce(t.tokens,0))
       ORDER BY days.day)
     FROM days LEFT JOIN scans_by_day s USING(day) LEFT JOIN tokens_by_day t USING(day)
    ) AS days
    FROM scan_totals CROSS JOIN finding_totals CROSS JOIN review_totals
  `, [activityTimeZone, accountId]);
  return { ...result.rows[0], time_zone: activityTimeZone };
}
