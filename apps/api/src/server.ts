import { projectReviewCatalog, projectReviewKeys, type ProjectReviewProvider } from "./project-review-models.js";
import { workspaceOverview } from "./workspace-overview.js";
import { registerWorkspaceAccess } from "./workspace-access.js";
import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { createClient } from "redis";
import { pool } from "./db.js";
import { findNpmCli, registerDashboardCodeReview, runDashboardCodeReview, type SavedCodeReview } from "./dashboard-code-review.js";
import { groqReview } from "./groq-review.js";
import { isUuid, QUEUE_NAME, type JobMessage } from "./types.js";
import multipart from "@fastify/multipart";
import { inspectSource, stageUpload, validateLocalPath } from "./intake.js";
import { IntakeError, intakeReasonMessage, type IntakeReasonCode } from "./intake-reasons.js";
import { assessmentDetailQuerySchema, createAssessmentSchema, createZipAssessmentSchema, validateTarget } from "./validation.js";
import { createDiscoveryScope, type DiscoveryScopeApproval } from "./discovery-scope-policy.js";
import type { DiscoveryScope } from "./discovery-contracts.js";
import { findDiscoveryProfile } from "./discovery/authorization-profiles.js";
import { getDiscoveryBudgetDto, resolveDiscoveryState } from "./discovery/assessment-summary.js";
import { registerZapImport, type ZapImportStore } from "./zap-import.js";
import { registerPassiveEvidence } from "./passive-evidence-api.js";
import { createPassiveEvidenceStore } from "./passive-evidence-store.js";

const app = Fastify({ logger: true });
registerWorkspaceAccess(app, process.env.SAPPHIRE_AI_REVIEW_PROXY_TOKEN?.trim());
const redis = createClient({ url: process.env.REDIS_URL ?? "redis://redis:6379/0" });
redis.on("error", (error) => app.log.error({ err: error }, "Redis client error"));
const artifactDir = process.env.ARTIFACT_DIR ?? "/artifacts";
const origins = (process.env.CORS_ORIGINS ?? "http://localhost:3000").split(",").map((v) => v.trim()).filter(Boolean);
await app.register(cors, { origin: origins, methods: ["GET", "POST"], allowedHeaders: ["Content-Type"] });
await app.register(multipart, { limits: { files: 1, fileSize: 100 * 1024 * 1024, fields: 5, parts: 6 } });

const zapStore: ZapImportStore = {
  async save(id, report, sourceSha256) {
    const result = await pool.query("INSERT INTO zap_report_imports (assessment_id,report,revision_id,source_sha256) SELECT id,$2::jsonb,$3,$4 FROM assessments WHERE id=$1 ON CONFLICT (assessment_id) DO UPDATE SET report=EXCLUDED.report, revision_id=EXCLUDED.revision_id, source_sha256=EXCLUDED.source_sha256, imported_at=now() RETURNING report,imported_at,revision_id,source_sha256", [id, JSON.stringify(report), randomUUID(), sourceSha256]);
    return result.rows[0] ?? null;
  },
  async load(id) {
    const result = await pool.query("SELECT z.report,z.imported_at,z.revision_id,z.source_sha256 FROM assessments a LEFT JOIN zap_report_imports z ON z.assessment_id=a.id WHERE a.id=$1", [id]);
    if (!result.rowCount) return { exists: false, value: null };
    const row = result.rows[0];
    return { exists: true, value: row.report ? { report: row.report, imported_at: row.imported_at, revision_id: row.revision_id, source_sha256: row.source_sha256 } : null };
  },
};
await app.register(async (scope) => registerZapImport(scope, zapStore));

const captureKeyHex = process.env.PASSIVE_CAPTURE_KEY_HEX;
if (captureKeyHex && !/^[0-9a-f]{64}$/i.test(captureKeyHex)) {
  throw new Error("PASSIVE_CAPTURE_KEY_HEX must contain 64 hexadecimal characters");
}
const captureKey = captureKeyHex ? Buffer.from(captureKeyHex, "hex") : undefined;
await app.register(async (scope) => registerPassiveEvidence(scope, createPassiveEvidenceStore(pool), captureKey));

const groqKey = process.env.GROQ_API_KEY?.trim();
const projectReviewProvider = projectReviewCatalog().preferred;

const npmCli = groqKey ? findNpmCli() : undefined;
const dashboardModel = groqKey && npmCli ? groqReview(groqKey) : undefined;
const reviewEvent = "ai_code_review.finished";
registerDashboardCodeReview(app, {
  origins,
  requireProxy: process.env.SAPPHIRE_AI_REVIEW_REQUIRE_PROXY === "1",
  proxyToken: process.env.SAPPHIRE_AI_REVIEW_PROXY_TOKEN?.trim(),
  async projectReview(assessmentId) {
    const result = await pool.query(
      "SELECT status,source_sha256,static_report,report,reason,updated_at FROM project_code_reviews WHERE assessment_id=$1",
      [assessmentId],
    );
    return result.rows[0] ?? null;
  },
  async controlProjectReview(assessmentId, action) {
    const result = await pool.query(`
      WITH changed AS (
        UPDATE project_code_reviews
        SET pause_requested=($2='pause'), cancel_requested=($2='stop'),
            reason=CASE WHEN $2='resume' AND reason='paused' THEN NULL ELSE reason END,
            updated_at=now()
        WHERE assessment_id=$1 AND NOT cancel_requested AND (
          ($2='pause' AND NOT pause_requested AND status IN ('waiting_for_scans','queued','running')) OR
          ($2='resume' AND pause_requested AND status IN ('waiting_for_scans','queued')
             AND consent_at > now() - interval '48 hours') OR
          ($2='stop' AND status IN ('waiting_for_scans','queued','running'))
        )
        RETURNING assessment_id
      )
      INSERT INTO audit_events (assessment_id,actor,event_type,details)
      SELECT assessment_id,'dashboard','ai_code_review.control',jsonb_build_object('action',$2::text)
      FROM changed
    `, [assessmentId, action]);
    return result.rowCount === 1;
  },
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

async function auditIntakeRejection(sourceType: "local_path" | "zip", reasonCode: string): Promise<void> {
  await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES (NULL, NULL, 'api', 'intake.rejected', $1)", [{ source_type: sourceType, reason_code: reasonCode }]);
}

function authorizedScope(assessmentId: string, targetUrl: string, attested: boolean): DiscoveryScope | null {
  if (!attested) return null;
  let target: URL;
  try { target = new URL(targetUrl); } catch { return null; }
  const profile = findDiscoveryProfile(target.origin);
  if (!profile) return null;
  const now = new Date();
  const approval: DiscoveryScopeApproval = {
    scope_id: randomUUID(), assessment_id: assessmentId, origin: profile.origin,
    path_mode: profile.path_mode, path_prefixes: profile.path_prefixes,
    pinned_ips: profile.pinned_ips, policy_revision: profile.policy_revision,
    authorization_actor: (process.env.DISCOVERY_AUTHORIZATION_ACTOR ?? "local-operator-attestation").slice(0, 120),
    authorized_at: now.toISOString(), expires_at: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
  };
  try {
    const scope = createDiscoveryScope(approval);
    // The submitted seed must itself be covered by the operator profile.
    const path = target.pathname.replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/";
    if (scope.path_mode === "prefix" && !scope.path_prefixes.some((prefix) => prefix === "/" || path === prefix || path.startsWith(`${prefix}/`))) return null;
    return scope;
  } catch { return null; }
}

app.get("/workspace/overview", async (request) => workspaceOverview(request.accountId));
app.get("/workspace/review-models", async () => projectReviewCatalog());

app.get("/health", async (_request, reply) => {
  let postgres = "unavailable";
  let redisStatus = "unavailable";
  try { await pool.query("SELECT 1"); postgres = "ok"; } catch { /* report degraded health */ }
  try { await redis.ping(); redisStatus = "ok"; } catch { /* report degraded health */ }
  const services = { api: "ok", postgres, redis: redisStatus };
  const healthy = postgres === "ok" && redisStatus === "ok";
  return reply.code(healthy ? 200 : 503).send({ status: healthy ? "ok" : "degraded", services });
});

async function createIntake(projectName: string, repositoryPath: string, sourceType: "local_path" | "zip", sourcePath: string, targetUrl: string, runtimeDiscoveryAuthorized: boolean, request: import("fastify").FastifyRequest, reply: import("fastify").FastifyReply, reviewProvider: ProjectReviewProvider | null = null) {
  const projectId = randomUUID();
  const assessmentId = randomUUID();
  const jobId = randomUUID();
  const scope = authorizedScope(assessmentId, targetUrl, runtimeDiscoveryAuthorized);
  if (runtimeDiscoveryAuthorized && !scope) {
    if (sourceType === "zip") await rm(sourcePath, { force: true }).catch(() => undefined);
    return reply.code(422).send({ detail: "Runtime discovery authorization must match a configured exact origin and valid scope profile" });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO projects (id, name, repository_path, source_type, source_location, intake_status, owner_account_id) VALUES ($1, $2, $3, $4, $5, 'queued', $6)", [projectId, projectName, repositoryPath, sourceType, repositoryPath, request.accountId]);
    await client.query("INSERT INTO assessments (id, project_id, target_url, status) VALUES ($1, $2, $3, 'queued')", [assessmentId, projectId, targetUrl]);
    if (reviewProvider) await client.query("INSERT INTO project_code_reviews (assessment_id,provider) VALUES ($1,$2)", [assessmentId, reviewProvider]);
    if (scope) await client.query("INSERT INTO discovery_scopes (id,assessment_id,scheme,host,port,path_mode,path_prefixes,allowed_methods,pinned_ips,policy_revision,policy_sha256,authorization_actor,authorized_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", [scope.scope_id,scope.assessment_id,scope.scheme,scope.host,scope.port,scope.path_mode,JSON.stringify(scope.path_prefixes),JSON.stringify(scope.allowed_methods),JSON.stringify(scope.pinned_ips),scope.policy_revision,scope.policy_sha256,scope.authorization_actor,scope.authorized_at,scope.expires_at]);
    await client.query("INSERT INTO tool_runs (id, assessment_id, tool_definition_id, status) VALUES ($1, $2, 'source-intake', 'queued')", [jobId, assessmentId]);
    await client.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'intake.requested', $3)", [assessmentId, jobId, { source_type: sourceType }]);
    await client.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'intake.accepted', $3)", [assessmentId, jobId, { source_type: sourceType, discovery_scope_id: scope?.scope_id ?? null, scope_policy_sha256: scope?.policy_sha256 ?? null, discovery_profile: scope ? scope.policy_revision : null, review_provider: reviewProvider }]);
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
    if (reviewProvider) await pool.query("UPDATE project_code_reviews SET status='incomplete',reason='queue_unavailable',updated_at=now() WHERE assessment_id=$1", [assessmentId]);
    await pool.query("INSERT INTO audit_events (assessment_id, tool_run_id, actor, event_type, details) VALUES ($1, $2, 'api', 'intake.failed', $3)", [assessmentId, jobId, { reason: "queue unavailable" }]);
    request.log.error({ err: error }, "Queue unavailable");
    return reply.code(503).send({ detail: "Assessment saved but the queue is unavailable" });
  }
  return reply.code(202).send({ assessment_id: assessmentId, job_id: jobId, status: "queued", runtime_discovery: { status: scope ? "authorized" : "not_authorized", detail: scope ? "Runtime discovery was authorized for the configured exact profile." : "Static intake is queued; runtime discovery was not authorized and will not be enqueued." } });
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
  return createIntake(parsed.data.project_name, canonicalPath, "local_path", canonicalPath, targetUrl, parsed.data.runtime_discovery_authorized === true, request, reply);
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
  } catch (error) {
    await rm(stagedPath, { force: true }).catch(() => undefined);
    const reasonCode: IntakeReasonCode = error instanceof IntakeError ? error.reasonCode : "intake_archive_malformed";
    await auditIntakeRejection("zip", reasonCode).catch(() => undefined);
    return reply.code(422).send({ detail: intakeReasonMessage(reasonCode), reason_code: reasonCode });
  }
  if (invalidFileField) { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "invalid_file_field").catch(() => undefined); return reply.code(422).send({ detail: "ZIP must be uploaded in the source field" }); }
  if (!staged) { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "zip_missing").catch(() => undefined); return reply.code(422).send({ detail: "A ZIP source file is required" }); }
  const parsed = createZipAssessmentSchema.safeParse(fields);
  if (!parsed.success) { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "invalid_input").catch(() => undefined); return reply.code(422).send({ detail: "Invalid assessment input", issues: parsed.error.issues }); }
  let targetUrl: string;
  try { targetUrl = parsed.data.target_url ? validateTarget(parsed.data.target_url) : ""; }
  catch { await rm(stagedPath, { force: true }).catch(() => undefined); await auditIntakeRejection("zip", "invalid_target").catch(() => undefined); return reply.code(422).send({ detail: "Invalid target" }); }
  const reviewProvider = parsed.data.ai_review_authorized
    ? parsed.data.ai_review_provider ?? (projectReviewProvider === "groq" ? "groq" : null)
    : null;
  if (parsed.data.ai_review_authorized && !reviewProvider) {
    await rm(stagedPath, { force: true }).catch(() => undefined);
    return reply.code(409).send({ detail: "Choose an AI review model and confirm sharing again." });
  }
  if (reviewProvider && !projectReviewKeys()[reviewProvider]) {
    await rm(stagedPath, { force: true }).catch(() => undefined);
    return reply.code(503).send({ detail: "The selected AI review model is unavailable. Choose a configured model." });
  }
  return createIntake(parsed.data.project_name, "ZIP upload", "zip", staged, targetUrl, parsed.data.runtime_discovery_authorized === true, request, reply, reviewProvider);
});

app.get("/assessments", async (request) => {
  const result = await pool.query("SELECT a.id,p.name AS project_name,p.source_type,p.source_identity_type,p.source_identity,p.source_languages,p.intake_status,a.target_url,a.status,a.coverage_status,a.created_at,(SELECT count(*) FROM discovered_routes r WHERE r.assessment_id=a.id)::int AS route_count,(SELECT COALESCE(jsonb_agg(x.route),'[]'::jsonb) FROM (SELECT jsonb_build_object('method',r.method,'path',r.path,'source_file',CASE WHEN r.source_file !~ '(^/|^[A-Za-z]:)' AND position(chr(92) in r.source_file)=0 AND r.source_file !~ '(^|/)\\.\\.(/|$)' THEN r.source_file ELSE NULL END,'source_line',r.source_line,'confidence',r.confidence) AS route FROM discovered_routes r WHERE r.assessment_id=a.id ORDER BY r.source_file,r.source_line NULLS LAST LIMIT 100) x) AS routes,(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',t.name,'category',t.category,'confidence',t.confidence,'evidence',t.evidence,'reason',t.reason) ORDER BY t.category,t.name),'[]'::jsonb) FROM detected_technologies t WHERE t.assessment_id=a.id) AS technologies,(SELECT COALESCE(jsonb_agg(jsonb_build_object('severity',f.severity,'code',f.code,'message',f.message) ORDER BY f.id),'[]'::jsonb) FROM intake_findings f WHERE f.assessment_id=a.id) AS findings,(SELECT count(*)::int FROM normalized_findings nf WHERE nf.assessment_id=a.id) AS normalized_finding_count,(SELECT COALESCE(jsonb_object_agg(severity,finding_count),'{}'::jsonb) FROM (SELECT severity,count(*)::int AS finding_count FROM normalized_findings nf WHERE nf.assessment_id=a.id GROUP BY severity) sev) AS severity_counts FROM assessments a JOIN projects p ON p.id=a.project_id WHERE p.owner_account_id=$1 ORDER BY a.created_at DESC LIMIT 100", [request.accountId]);
  const reviews = await pool.query(`
    SELECT assessment_id,status,reason,updated_at,pause_requested,cancel_requested,
           (report->>'total_files')::int AS total_files,
           jsonb_array_length(report->'reviewed_files') AS reviewed_files,
           jsonb_array_length(report->'findings') AS findings
    FROM project_code_reviews WHERE assessment_id=ANY($1::uuid[])
  `, [result.rows.map(({ id }) => id)]);
  const byAssessment = new Map(reviews.rows.map((review) => [review.assessment_id, review]));
  return result.rows.map((row) => ({ ...row, id: String(row.id), created_at: row.created_at.toISOString(), ai_review: byAssessment.get(row.id) ?? null }));
});

app.get<{ Params: { assessment_id: string } }>("/assessments/:assessment_id", async (request, reply) => {
  const id = parseId(request.params.assessment_id);
  if (!id) return reply.code(400).send({ detail: "Assessment ID is invalid" });
  const query = assessmentDetailQuerySchema.safeParse(request.query);
  if (!query.success) return reply.code(400).send({ detail: "Invalid pagination parameters" });
  const { limit, endpoint_cursor: endpointCursor, match_cursor: matchCursor } = query.data;
  const result = await pool.query("SELECT a.id,p.name AS project_name,p.source_type,p.source_identity_type,p.source_identity,p.source_file_count,p.source_total_bytes,p.source_languages,p.intake_status,a.target_url,a.status,a.coverage_status,a.created_at FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1", [id]);
  if (!result.rowCount) return reply.code(404).send({ detail: "Assessment not found" });
  const [jobs, technologies, routes, findings, artifacts, groups, scopes, endpoints, endpointCount, matches, matchCount, classCounts, reasonCounts, zapImport] = await Promise.all([
    pool.query("SELECT id,tool_definition_id AS tool,status,coverage_status,tool_version,adapter_version,config_id,config_sha256,exit_code,failure_reason_code,counters,provenance,started_at,finished_at,cancel_requested FROM tool_runs WHERE assessment_id=$1 ORDER BY created_at", [id]),
    pool.query("SELECT name, category, confidence, evidence, reason FROM detected_technologies WHERE assessment_id=$1 ORDER BY category,name", [id]),
    pool.query("SELECT method,path,CASE WHEN source_file !~ '(^/|^[A-Za-z]:)' AND position(chr(92) in source_file)=0 AND source_file !~ '(^|/)\\.\\.(/|$)' THEN source_file ELSE NULL END AS source_file,source_line,confidence FROM discovered_routes WHERE assessment_id=$1 ORDER BY source_file,source_line NULLS LAST,method,path", [id]),
    pool.query("SELECT severity, code, message, created_at FROM intake_findings WHERE assessment_id=$1 ORDER BY id", [id]),
    pool.query("SELECT id,tool_run_id,artifact_kind,relative_path,media_type,sha256,byte_size,metadata,created_at FROM scan_artifacts WHERE assessment_id=$1 ORDER BY created_at,artifact_kind", [id]),
    pool.query("SELECT g.id,g.fingerprint,g.title,g.severity,count(f.id)::int AS duplicate_count,COALESCE(jsonb_agg(jsonb_build_object('id',f.id,'tool_run_id',f.tool_run_id,'artifact_id',f.artifact_id,'raw_pointer',f.raw_pointer,'finding_type',f.finding_type,'rule_id',f.rule_id,'cve_id',f.cve_id,'title',f.title,'message',f.message,'severity',f.severity,'confidence',f.confidence,'source_file',f.source_file,'start_line',f.start_line,'start_column',f.start_column,'end_line',f.end_line,'end_column',f.end_column,'evidence',f.evidence) ORDER BY f.created_at,f.id) FILTER (WHERE f.id IS NOT NULL),'[]'::jsonb) AS findings FROM finding_groups g LEFT JOIN normalized_findings f ON f.group_id=g.id WHERE g.assessment_id=$1 GROUP BY g.id ORDER BY CASE g.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,g.title LIMIT 500", [id]),
    pool.query("SELECT id,scheme,host,port,path_mode,path_prefixes,policy_revision,policy_sha256,authorized_at,expires_at FROM discovery_scopes WHERE assessment_id=$1 ORDER BY created_at DESC", [id]),
    pool.query("SELECT id,tool_run_id,artifact_id,scheme,host,port,path,observed_method AS method,status_code,content_type,content_length,first_seen_at,last_seen_at,tool_version,config_sha256,scope_policy_sha256 FROM runtime_endpoints WHERE assessment_id=$1 ORDER BY id LIMIT $2 OFFSET $3", [id,limit,endpointCursor]),
    pool.query("SELECT count(*)::int AS count FROM runtime_endpoints WHERE assessment_id=$1", [id]),
    pool.query("SELECT id,runtime_endpoint_id,coverage_class,source_method,source_route,source_file,source_line,candidate_source_route_ids,reason_code,evidence FROM endpoint_route_matches WHERE assessment_id=$1 ORDER BY id LIMIT $2 OFFSET $3", [id,limit,matchCursor]),
    pool.query("SELECT count(*)::int AS count FROM endpoint_route_matches WHERE assessment_id=$1", [id]),
    pool.query("SELECT coverage_class,count(*)::int AS count FROM endpoint_route_matches WHERE assessment_id=$1 GROUP BY coverage_class", [id]),
    pool.query("SELECT reason_code,count(*)::int AS count FROM endpoint_route_matches WHERE assessment_id=$1 GROUP BY reason_code ORDER BY reason_code", [id]),
    pool.query("SELECT revision_id, source_sha256, imported_at, report->>'tool' AS tool, report->>'zapVersion' AS zap_version, report->>'coverage' AS coverage, report->'coverageReasons' AS coverage_reasons, report->'passiveCapture' AS passive_capture, jsonb_array_length(report->'findings') AS finding_count FROM zap_report_imports WHERE assessment_id=$1", [id]),
  ]);
  const row = result.rows[0];
  const endpointTotal = Number(endpointCount.rows[0]?.count ?? 0);
  const discoveryRuns = jobs.rows.filter((job) => job.tool === "httpx" || job.tool === "katana");
  const coverageCounts = { matched: 0, source_only: 0, runtime_only: 0, unresolved: 0 };
  for (const item of classCounts.rows) if (Object.hasOwn(coverageCounts, item.coverage_class)) coverageCounts[item.coverage_class as keyof typeof coverageCounts] = Number(item.count);
  const discoveryState = resolveDiscoveryState(discoveryRuns, endpointTotal, scopes.rowCount ?? scopes.rows.length);
  return {
    ...row, id: String(row.id), created_at: row.created_at.toISOString(),
    job: jobs.rows.map((job) => ({ ...job, id: String(job.id), started_at: job.started_at?.toISOString() ?? null, finished_at: job.finished_at?.toISOString() ?? null })),
    technologies: technologies.rows, routes: routes.rows, findings: findings.rows,
    artifacts: artifacts.rows.map((artifact) => ({ ...artifact, id: String(artifact.id), tool_run_id: String(artifact.tool_run_id), created_at: artifact.created_at.toISOString() })),
    finding_groups: groups.rows,
    zap_report: zapImport.rowCount ? {
      ...zapImport.rows[0],
      status: "imported",
      passive_capture: zapImport.rows[0].passive_capture ?? undefined,
      imported_at: zapImport.rows[0].imported_at.toISOString(),
    } : { status: "missing" },
    discovery: { state: discoveryState, budget: getDiscoveryBudgetDto(), scope: scopes.rows[0] ?? null,
      counts: coverageCounts,
      reason_counts: Object.fromEntries(reasonCounts.rows.map((item) => [item.reason_code, Number(item.count)])),
      endpoint_count: endpointTotal, match_count: Number(matchCount.rows[0]?.count ?? 0),
      endpoints: { items: endpoints.rows.map((item) => ({ ...item, id: String(item.id), tool_run_id: String(item.tool_run_id), artifact_id: String(item.artifact_id), first_seen_at: item.first_seen_at.toISOString(), last_seen_at: item.last_seen_at.toISOString() })), limit, cursor: endpointCursor, next_cursor: endpointCursor + endpoints.rowCount! < endpointTotal ? endpointCursor + endpoints.rowCount! : null },
      matches: { items: matches.rows.map((item) => ({ ...item, id: String(item.id), runtime_endpoint_id: item.runtime_endpoint_id ? String(item.runtime_endpoint_id) : null, candidate_source_route_ids: item.candidate_source_route_ids.map(String) })), limit, cursor: matchCursor, next_cursor: matchCursor + matches.rowCount! < Number(matchCount.rows[0]?.count ?? 0) ? matchCursor + matches.rowCount! : null },
    },
  };
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
    const review = await client.query("UPDATE project_code_reviews SET cancel_requested=true,updated_at=now() WHERE assessment_id=$1 AND status IN ('waiting_for_scans','queued','running') AND NOT cancel_requested", [assessmentId]);
    if (!result.rowCount && !review.rowCount) { await client.query("ROLLBACK"); return reply.code(409).send({ detail: "Assessment has no cancellable runs" }); }
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
