import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { isUuid } from "./types.js";
import { normalizeZapReport } from "./zap-report.js";

type PassiveCapture = {
  source: "cli_reported";
  run_id: string;
  recorded_exchanges: number;
  recorded_origins: number;
  authentication: "unverified";
};

export type ZapReport = ReturnType<typeof normalizeZapReport> & { passiveCapture?: PassiveCapture };
export type StoredZapReport = { report: ZapReport; imported_at: Date; revision_id: string; source_sha256: string | null };
export interface ZapImportStore {
  save(assessmentId: string, report: ZapReport, sourceSha256: string): Promise<StoredZapReport | null>;
  load(assessmentId: string): Promise<{ exists: boolean; value: StoredZapReport | null }>;
}

export function zapSummary(value: StoredZapReport | null) {
  if (!value) return { status: "missing" as const };
  const { report } = value;
  return { status: "imported" as const, revision_id: value.revision_id, source_sha256: value.source_sha256, imported_at: value.imported_at.toISOString(), tool: report.tool,
    zap_version: report.zapVersion, coverage: report.coverage, coverage_reasons: report.coverageReasons,
    finding_count: report.findings.length,
    ...(report.passiveCapture ? { passive_capture: report.passiveCapture } : {}) };
}

function passiveCapture(query: Record<string, unknown>): PassiveCapture | undefined {
  const { passive_run_id: runId, capture_exchanges: exchanges, capture_origins: origins } = query;
  if (runId === undefined && exchanges === undefined && origins === undefined) return;
  if (typeof runId !== "string" || !isUuid(runId) ||
      typeof exchanges !== "string" || !/^[1-9]\d{0,2}$/.test(exchanges) || Number(exchanges) > 200 ||
      typeof origins !== "string" || !/^[1-9]\d{0,2}$/.test(origins) || Number(origins) > Number(exchanges)) {
    throw new Error("Invalid passive capture metadata");
  }
  return {
    source: "cli_reported",
    run_id: runId,
    recorded_exchanges: Number(exchanges),
    recorded_origins: Number(origins),
    authentication: "unverified",
  };
}

function pagination(query: unknown, allowRevision = false): { offset: number; limit: number } | null {
  if (!query || typeof query !== "object") return null;
  const q = query as Record<string, unknown>;
  if (Object.keys(q).some((key) => key !== "offset" && key !== "limit" && !(allowRevision && key === "revision_id"))) return null;
  const parse = (value: unknown, fallback: number) => value === undefined ? fallback : typeof value === "string" && /^(0|[1-9]\d{0,5})$/.test(value) ? Number(value) : NaN;
  const offset = parse(q.offset, 0), limit = parse(q.limit, 50);
  return Number.isSafeInteger(offset) && limit >= 1 && limit <= 100 ? { offset, limit } : null;
}

export async function registerZapImport(app: FastifyInstance, store: ZapImportStore): Promise<void> {
  // This parser is encapsulated to this plugin and never echoes the source or parser errors.
  app.removeContentTypeParser("application/json");
  app.addContentTypeParser("application/json", { parseAs: "buffer", bodyLimit: 10 * 1024 * 1024 }, (_req, body, done) => done(null, body));
  app.setErrorHandler((error, _request, reply) => {
    const status = typeof error === "object" && error !== null && "statusCode" in error && error.statusCode === 413 ? 413 : 400;
    void reply.code(status).send({ detail: status === 413 ? "Report exceeds size limit" : "Invalid report request" });
  });

  app.post<{ Params: { assessment_id: string }; Body: Buffer; Querystring: Record<string, unknown> }>("/assessments/:assessment_id/zap-report", { bodyLimit: 10 * 1024 * 1024 }, async (request, reply) => {
    if (!isUuid(request.params.assessment_id)) return reply.code(400).send({ detail: "Assessment ID is invalid" });
    let capture: PassiveCapture | undefined;
    try { capture = passiveCapture(request.query); }
    catch { return reply.code(400).send({ detail: "Invalid passive capture metadata" }); }
    let report: ZapReport;
    try {
      if (!Buffer.isBuffer(request.body)) throw new Error("invalid body");
      report = normalizeZapReport(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(request.body)));
      if (capture) report.passiveCapture = capture;
    } catch { return reply.code(422).send({ detail: "Invalid or unsupported ZAP report" }); }
    try {
      const value = await store.save(request.params.assessment_id, report, createHash("sha256").update(request.body).digest("hex"));
      if (!value) return reply.code(404).send({ detail: "Assessment not found" });
      return reply.code(200).send(zapSummary(value));
    } catch { return reply.code(503).send({ detail: "Could not save report" }); }
  });

  app.get<{ Params: { assessment_id: string } }>("/assessments/:assessment_id/zap-report/findings", async (request, reply) => {
    if (!isUuid(request.params.assessment_id)) return reply.code(400).send({ detail: "Assessment ID is invalid" });
    const page = pagination(request.query);
    if (!page) return reply.code(400).send({ detail: "Invalid pagination" });
    try {
      const { exists, value } = await store.load(request.params.assessment_id);
      if (!exists) return reply.code(404).send({ detail: "Assessment not found" });
      if (!value) return reply.code(404).send({ detail: "No ZAP report imported" });
      const findings = value.report.findings;
      return { ...page, revision_id: value.revision_id, total: findings.length, items: findings.slice(page.offset, page.offset + page.limit).map((finding) => ({
        ruleId: finding.ruleId, severity: finding.severity, rawPointer: finding.rawPointer, instance_count: finding.instances.length,
      })) };
    } catch { return reply.code(503).send({ detail: "Could not read report" }); }
  });

  app.get<{ Params: { assessment_id: string; finding_index: string } }>("/assessments/:assessment_id/zap-report/findings/:finding_index/instances", async (request, reply) => {
    if (!isUuid(request.params.assessment_id) || !/^(0|[1-9]\d{0,5})$/.test(request.params.finding_index)) return reply.code(400).send({ detail: "Invalid identifier" });
    const page = pagination(request.query, true);
    if (!page) return reply.code(400).send({ detail: "Invalid pagination" });
    const revision = (request.query as Record<string, unknown>).revision_id;
    if (typeof revision !== "string" || !isUuid(revision)) return reply.code(400).send({ detail: "Revision ID is required" });
    try {
      const { exists, value } = await store.load(request.params.assessment_id);
      if (!exists) return reply.code(404).send({ detail: "Assessment not found" });
      if (value && value.revision_id !== revision) return reply.code(409).send({ detail: "Report revision changed" });
      const finding = value?.report.findings[Number(request.params.finding_index)];
      if (!finding) return reply.code(404).send({ detail: "Finding not found" });
      return { ...page, revision_id: value!.revision_id, total: finding.instances.length, items: finding.instances.slice(page.offset, page.offset + page.limit) };
    } catch { return reply.code(503).send({ detail: "Could not read report" }); }
  });
}
