import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { importPassiveEvidence } from "./passive-evidence.js";
import { isUuid } from "./types.js";

type Imported = ReturnType<typeof importPassiveEvidence>;
export type PassiveEvidenceRecord = Omit<Imported, "har"> & { run_id: string };

export interface PassiveEvidenceStore {
  put(assessmentId: string, evidence: PassiveEvidenceRecord): Promise<"saved" | "missing" | "conflict">;
  get(assessmentId: string, runId: string): Promise<PassiveEvidenceRecord | null>;
  latest(assessmentId: string): Promise<PassiveEvidenceRecord | null>;
}

export async function registerPassiveEvidence(
  app: FastifyInstance, store: PassiveEvidenceStore, key?: Buffer,
): Promise<void> {
  app.setErrorHandler((error, request, reply) => {
    const status = error instanceof Error && "statusCode" in error ? error.statusCode : undefined;
    if (status === 400 || status === 413 || status === 415) {
      return reply.code(status).send({ detail: "Invalid passive capture payload" });
    }
    request.log.error({ code: "passive_capture_request_failed" });
    return reply.code(500).send({ detail: "Passive capture request failed" });
  });

  app.post<{ Params: { assessment_id: string }; Body: unknown }>(
    "/assessments/:assessment_id/passive-captures",
    { bodyLimit: 10 * 1024 * 1024 },
    async (request, reply) => {
      const assessmentId = request.params.assessment_id;
      if (!isUuid(assessmentId)) return reply.code(400).send({ detail: "Invalid assessment ID" });
      const body = request.body;
      if (!body || typeof body !== "object" || !("har" in body)) {
        return reply.code(422).send({ detail: "Invalid passive capture payload" });
      }
      const suppliedManifest = "manifest" in body || "signature" in body;
      if (suppliedManifest && !key) {
        return reply.code(503).send({ detail: "Passive capture verification is unavailable" });
      }
      let evidence: PassiveEvidenceRecord;
      try {
        const imported = importPassiveEvidence(body, key);
        const { har: _har, ...metadata } = imported;
        const manifest = "manifest" in metadata ? metadata.manifest : undefined;
        if (suppliedManifest && (!manifest || manifest.scope_id.toLowerCase() !== assessmentId.toLowerCase())) {
          return reply.code(422).send({ detail: "Invalid passive capture manifest for this assessment" });
        }
        evidence = { ...metadata, run_id: manifest?.run_id ?? randomUUID() };
      } catch {
        return reply.code(422).send({ detail: "Invalid passive capture payload" });
      }
      const result = await store.put(assessmentId, evidence);
      if (result === "missing") return reply.code(404).send({ detail: "Assessment not found" });
      if (result === "conflict") return reply.code(409).send({ detail: "Conflicting passive capture run" });
      return reply.header("Cache-Control", "no-store").code(201).send(evidence);
    },
  );

  app.get<{ Params: { assessment_id: string } }>(
    "/assessments/:assessment_id/passive-captures/latest",
    async (request, reply) => {
      const assessmentId = request.params.assessment_id;
      if (!isUuid(assessmentId)) return reply.code(400).send({ detail: "Invalid assessment ID" });
      return reply.header("Cache-Control", "no-store").send(await store.latest(assessmentId));
    },
  );

  app.get<{ Params: { assessment_id: string; run_id: string } }>(
    "/assessments/:assessment_id/passive-captures/:run_id",
    async (request, reply) => {
      const { assessment_id: assessmentId, run_id: runId } = request.params;
      if (!isUuid(assessmentId) || !isUuid(runId)) {
        return reply.code(400).send({ detail: "Invalid assessment or run ID" });
      }
      const evidence = await store.get(assessmentId, runId);
      if (!evidence) return reply.code(404).send({ detail: "Passive capture not found" });
      return reply.header("Cache-Control", "no-store").send(evidence);
    },
  );
}
