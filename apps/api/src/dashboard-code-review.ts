import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { auditDependencies } from "./dependency-audit.js";
import { maxReviewFiles, reviewCode, type ReviewModel } from "./code-review.js";
import { isUuid } from "./types.js";

const sourceFile = /^[a-zA-Z0-9][\w. -]{0,180}\.(?:[cm]?[jt]sx?|py|go|java|cs|rs|rb|php)$/i;
const windowsDevice = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])\./i;
const inputSchema = z.object({
  share_with_providers: z.literal(true),
  manifest: z.string().min(1).max(64 * 1024),
  lockfile: z.string().min(1).max(1024 * 1024),
  sources: z.array(z.object({
    name: z.string().regex(sourceFile).refine((name) => !windowsDevice.test(name)),
    text: z.string().min(1).refine((text) => Buffer.byteLength(text) <= 8192 && !text.includes("\0")),
  }).strict()).min(1).max(maxReviewFiles).refine(
    (files) => new Set(files.map(({ name }) => name.toLowerCase())).size === files.length,
  ),
}).strict();

type ReviewInput = z.infer<typeof inputSchema>;
type Report = Awaited<ReturnType<typeof reviewCode>>;
export type SavedCodeReview = { report: Report; created_at: string };
type ReviewStore = {
  exists(assessmentId: string): Promise<boolean>;
  latest(assessmentId: string): Promise<SavedCodeReview | null>;
  save(assessmentId: string, report: Report): Promise<SavedCodeReview>;
};

export function findNpmCli() {
  const bin = dirname(process.execPath);
  return [
    process.env.npm_execpath,
    join(bin, "node_modules/npm/bin/npm-cli.js"),
    join(bin, "../lib/node_modules/npm/bin/npm-cli.js"),
  ].find((path) => path && existsSync(path));
}

export async function runDashboardCodeReview(input: ReviewInput, model: ReviewModel, npmCli: string) {
  const directory = await mkdtemp(join(tmpdir(), "sapphire-dashboard-review-"));
  try {
    await writeFile(join(directory, "package.json"), input.manifest);
    await writeFile(join(directory, "package-lock.json"), input.lockfile);
    for (const { name, text } of input.sources) {
      await writeFile(join(directory, name), text);
    }
    const audit = await auditDependencies(directory, npmCli);
    const auditFile = join(directory, "dependency-audit.json");
    await writeFile(auditFile, JSON.stringify(audit));
    return await reviewCode(directory, auditFile, input.sources.map(({ name }) => name), model);
  } finally {
    await rm(directory, { recursive: true, force: true, maxRetries: 2 });
  }
}

export function registerDashboardCodeReview(app: FastifyInstance, options: {
  origins: string[];
  requireProxy?: boolean;
  proxyToken?: string;
  store: ReviewStore;
  run?: (input: ReviewInput) => Promise<Report>;
}) {
  const path = "/assessments/:assessment_id/ai-code-review";
  let running = false;

  const dashboardOnly = {
    async onRequest(request: FastifyRequest, reply: FastifyReply) {
      if (options.requireProxy) {
        const token = request.headers["x-sapphire-ai-review-proxy"];
        const digest = (value: string) => createHash("sha256").update(value).digest();
        if (!options.proxyToken || typeof token !== "string" ||
            !timingSafeEqual(digest(options.proxyToken), digest(token))) {
          return reply.code(403).send({ detail: "Use the authenticated Dashboard for AI Code Review" });
        }
        return;
      }
      if (!request.headers.origin || !options.origins.includes(request.headers.origin)) {
        return reply.code(403).send({ detail: "Dashboard origin is not allowed" });
      }
    },
  };

  app.get<{ Params: { assessment_id: string } }>(path, dashboardOnly, async (request, reply) => {
    const id = request.params.assessment_id;
    if (!isUuid(id)) return reply.code(400).send({ detail: "Assessment ID is invalid" });
    reply.header("Cache-Control", "no-store");
    const saved = await options.store.latest(id);
    if (!saved) return reply.code(404).send({ detail: "No AI Code Review saved for this assessment" });
    return saved;
  });

  app.post<{ Params: { assessment_id: string }; Body: unknown }>(path, {
    ...dashboardOnly,
    bodyLimit: 2 * 1024 * 1024,
  }, async (request, reply) => {
    const id = request.params.assessment_id;
    if (!isUuid(id)) return reply.code(400).send({ detail: "Assessment ID is invalid" });
    reply.header("Cache-Control", "no-store");
    const run = options.run;
    if (!run) return reply.code(503).send({ detail: "Configure GROQ_API_KEY and npm on the API server" });
    const parsed = inputSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(422).send({ detail: "Confirm sharing and provide a manifest, lockfile and 1–8 unique source files (up to 8 KiB each)" });
    }
    if (running) return reply.code(409).send({ detail: "An AI Code Review is already running" });
    running = true;
    try {
      if (!(await options.store.exists(id))) {
        return reply.code(404).send({ detail: "Assessment not found" });
      }
      const result = await run(parsed.data);
      const saved = await options.store.save(id, result);
      return reply.code(201).send(saved);
    } catch {
      request.log.error("Could not run or save the AI Code Review");
      return reply.code(503).send({ detail: "Could not run or save the AI Code Review" });
    } finally {
      running = false;
    }
  });
}
