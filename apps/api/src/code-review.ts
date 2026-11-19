import { createHash } from "node:crypto";
import { open, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { z } from "zod";

export const maxReviewFiles = 8;
const maxSourceBytes = 8192;
const maxPromptBytes = 24_000;
const severity = z.enum(["info", "low", "moderate", "high", "critical"]);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const status = z.enum(["clean", "findings", "incomplete"]);
const auditFailure = z.enum([
  "invalid_arguments", "missing_unreadable_or_unsupported_input", "npm_audit_failed",
  "invalid_npm_audit_report", "local_audit_error",
]);
const auditSchema = z.object({
  schema_version: z.literal(1),
  ecosystem: z.literal("npm"),
  source: z.literal("npm-audit"),
  registry: z.literal("https://registry.npmjs.org/"),
  status,
  reason: auditFailure.optional(),
  lockfile_sha256: digest.nullable(),
  findings: z.array(z.object({
    package: z.string().max(250),
    severity,
    instances: z.array(z.object({ version: z.string().max(128) })).min(1),
    advisories: z.array(z.object({ id: z.string().regex(/^npm:\d+$/) })),
  })),
});

export const modelReviewSchema = z.object({
  findings: z.array(z.object({
    file: z.string().min(1).max(512),
    line: z.number().int().positive(),
    severity,
    title: z.string().trim().min(1).max(180),
    remediation: z.string().trim().min(1).max(600),
  }).strict()).max(12),
  coverage_gaps: z.array(z.string().trim().min(1).max(240)).max(8),
}).strict();

export interface ReviewModel {
  readonly name: string;
  review(data: string): Promise<unknown>;
}

export class ReviewModelRequestError extends Error {
  constructor(readonly reason: "model_rate_limited" | "model_authentication_failed") {
    super(reason);
  }
}

class ReviewInputError extends Error {}

async function readBounded(path: string, limit: number) {
  if (!(await stat(path)).isFile()) throw new ReviewInputError("file_limit_or_type");
  const file = await open(path, "r");
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > limit) throw new ReviewInputError("file_limit_or_type");
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > limit) throw new ReviewInputError("file_limit_or_type");
    return buffer.subarray(0, length);
  } finally {
    await file.close();
  }
}

async function auditContext(project: string, reportFile: string) {
  const raw = await readBounded(reportFile, 1_048_576);
  // Windows PowerShell 5 redirection emits UTF-16LE. Newer shells usually emit UTF-8.
  const encoding = raw[0] === 0xff && raw[1] === 0xfe ? "utf16le" : "utf8";
  const report = auditSchema.safeParse(JSON.parse(raw.toString(encoding).replace(/^\uFEFF/, "")));
  if (!report.success) throw new ReviewInputError("invalid_dependency_report");
  const audit = report.data;
  if ((audit.status === "findings") !== (audit.findings.length > 0) ||
      (audit.status !== "incomplete" && !audit.lockfile_sha256)) {
    throw new ReviewInputError("invalid_dependency_report");
  }

  let fingerprint: string | null = null;
  try {
    const lock = await readBounded(await scopedPath(project, "package-lock.json"), 16_777_216);
    fingerprint = createHash("sha256").update(lock).digest("hex");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (fingerprint !== audit.lockfile_sha256) throw new ReviewInputError("dependency_report_lockfile_mismatch");

  const levels = severity.options;
  const focus = [...audit.findings].sort((left, right) =>
    levels.indexOf(right.severity) - levels.indexOf(left.severity)
  ).slice(0, 16).map(finding => ({
    package: finding.package,
    severity: finding.severity,
    versions: [...new Set(finding.instances.map(instance => instance.version))].slice(0, 5),
    advisory_ids: finding.advisories.slice(0, 5).map(advisory => advisory.id),
  }));
  return {
    status: audit.status,
    ...(audit.reason ? { reason: audit.reason } : {}),
    lockfile_sha256: fingerprint,
    lockfile_verified: fingerprint !== null,
    finding_count: audit.findings.length,
    included_findings: focus,
  };
}

async function scopedPath(project: string, file: string) {
  if (isAbsolute(file) || file.includes(":") || file.split(/[\\/]/).includes("..")) {
    throw new ReviewInputError("file_outside_scope");
  }
  const path = await realpath(resolve(project, file));
  const within = relative(project, path);
  if (!within || within === ".." || within.startsWith(`..${sep}`) || isAbsolute(within)) {
    throw new ReviewInputError("file_outside_scope");
  }
  return path;
}

export function incompleteCodeReview(reason: string, dependencyAudit: Awaited<ReturnType<typeof auditContext>> | null = null) {
  return {
    schema_version: 1,
    status: "incomplete" as const,
    reason,
    dependency_audit: dependencyAudit,
    reviewed_files: [],
    findings: [],
  };
}

export async function reviewCode(projectDirectory: string, reportFile: string, files: readonly string[], model: ReviewModel) {
  if (files.length === 0 || files.length > maxReviewFiles) return incompleteCodeReview("file_count_limit");
  let dependencyAudit: Awaited<ReturnType<typeof auditContext>> | null = null;
  const sources = new Map<string, string[]>();
  try {
    const project = await realpath(projectDirectory);
    dependencyAudit = await auditContext(project, reportFile);
    for (const file of files) {
      const path = await scopedPath(project, file);
      const name = relative(project, path).split(sep).join("/");
      if (sources.has(name) || !/\.(?:[cm]?[jt]sx?|py|go|java|cs|rs|rb|php)$/i.test(name) ||
          name.split("/").some(part => part.startsWith(".") || part.toLowerCase() === "node_modules")) {
        throw new ReviewInputError("unsupported_or_duplicate_source");
      }
      const source = new TextDecoder("utf-8", { fatal: true }).decode(await readBounded(path, maxSourceBytes));
      if (source.includes("\0")) throw new ReviewInputError("unsupported_or_duplicate_source");
      sources.set(name, source.split(/\r\n|\n|\r/));
    }
  } catch (error) {
    return incompleteCodeReview(error instanceof ReviewInputError ? error.message : "invalid_or_unreadable_input", dependencyAudit);
  }

  const data = JSON.stringify({
    dependency_audit: dependencyAudit,
    sources: [...sources].map(([file, lines]) => ({ file, lines })),
  });
  if (Buffer.byteLength(data) > maxPromptBytes) return incompleteCodeReview("context_limit", dependencyAudit);

  let raw: unknown;
  try {
    raw = await model.review(data);
  } catch (error) {
    const reason = error instanceof ReviewModelRequestError ? error.reason : "model_request_failed";
    return incompleteCodeReview(reason, dependencyAudit);
  }
  const result = modelReviewSchema.safeParse(raw);
  if (!result.success) return incompleteCodeReview("invalid_model_report", dependencyAudit);
  const findings = [];
  for (const finding of result.data.findings) {
    const evidence = sources.get(finding.file)?.[finding.line - 1]?.trim();
    if (!evidence) return incompleteCodeReview("invalid_model_citation", dependencyAudit);
    findings.push({ ...finding, evidence: evidence.slice(0, 500) });
  }
  return {
    schema_version: 1,
    status: "reviewed" as const,
    model: model.name,
    dependency_audit: dependencyAudit,
    reviewed_files: [...sources.keys()],
    findings,
    coverage_gaps: result.data.coverage_gaps,
  };
}
