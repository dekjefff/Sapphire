import { createHmac, timingSafeEqual } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { pool } from "./db.js";
import { isUuid } from "./types.js";

declare module "fastify" {
  interface FastifyRequest {
    accountId: string;
  }
}

const assessmentAccess =
  "SELECT 1 FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.owner_account_id=$2";
const artifactAccess =
  "SELECT 1 FROM scan_artifacts r JOIN assessments a ON a.id=r.assessment_id JOIN projects p ON p.id=a.project_id WHERE r.id=$1 AND p.owner_account_id=$2";
const jobAccess =
  "SELECT 1 FROM tool_runs r JOIN assessments a ON a.id=r.assessment_id JOIN projects p ON p.id=a.project_id WHERE r.id=$1 AND p.owner_account_id=$2";

export function registerWorkspaceAccess(app: FastifyInstance, secret?: string) {
  app.decorateRequest("accountId", "");
  app.addHook("onRequest", async (request, reply) => {
    if (request.routeOptions.url === "/health") return;

    const id = request.headers["x-sapphire-account"];
    const timestamp = request.headers["x-sapphire-account-time"];
    const signature = request.headers["x-sapphire-account-signature"];
    if (!secret || secret.length < 32 || typeof id !== "string" || !isUuid(id) ||
        typeof timestamp !== "string" || !/^\d{13}$/.test(timestamp) ||
        Math.abs(Date.now() - Number(timestamp)) > 60_000 ||
        typeof signature !== "string" || !/^[a-f0-9]{64}$/.test(signature)) {
      return reply.code(401).send({ detail: "Sign in to Sapphire" });
    }

    const expected = createHmac("sha256", secret)
      .update([id, timestamp, request.method, request.url].join("\n"))
      .digest();
    if (!timingSafeEqual(expected, Buffer.from(signature, "hex"))) {
      return reply.code(401).send({ detail: "Sign in to Sapphire" });
    }

    request.accountId = id;
    const params = request.params as {
      assessment_id?: string;
      artifact_id?: string;
      job_id?: string;
    } | undefined;
    const resource = params?.assessment_id
      ? { id: params.assessment_id, query: assessmentAccess, name: "Assessment" }
      : params?.artifact_id
        ? { id: params.artifact_id, query: artifactAccess, name: "Artifact" }
        : params?.job_id
          ? { id: params.job_id, query: jobAccess, name: "Job" }
          : null;
    if (!resource) return;

    if (!isUuid(resource.id)) return reply.code(400).send({ detail: resource.name + " ID is invalid" });
    const result = await pool.query(resource.query, [resource.id, id]);
    if (!result.rowCount) return reply.code(404).send({ detail: resource.name + " not found" });
  });
}
