import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { modelReviewSchema, ReviewModelRequestError, type ReviewModel } from "./code-review.js";
import { maxReviewAttempts, reviewBackoffMs } from "./review-retry.js";

const sourceExtension = /\.(?:[cm]?[jt]sx?|py|go|java|cs|rs|rb|php|c|h|cpp|swift|kt|scala|vue|svelte|sql)$/i;
const maxFileBytes = 256 * 1024;
const maxPayloadBytes = 4400;
// Reserve bytes conservatively as input tokens, plus message/schema overhead and the provider output cap.
const promptOverhead = 1024;
const outputTokens = 2048;
const minuteTokens = 7600;
export const projectReviewBudget = { requests: 40, estimatedTokens: 200_000, durationMs: 30 * 60 * 1000 };

export type ScannerReport = {
  schema_version: 1;
  assessment_id: string;
  source_sha256: string;
  tools: { tool: "semgrep" | "trivy"; status: string; findings: number; failure_code: string | null }[];
  intake_gap_codes: string[];
  finding_count: number;
  findings: { id: string; tool: string; type: string; file: string | null; line: number | null; severity: string; rule: string | null }[];
};

type Finding = {
  file: string; line: number; severity: string; title: string; remediation: string; evidence: string;
  related_static_finding_ids: string[];
};
type FileResult = { file: string; reason: string };
export type ModelAttemptFailure = {
  attempt: number;
  request_number: number;
  reason: string;
  http_status: number | null;
  provider_error_code: string | null;
  retry_scheduled: boolean;
};
export type ProjectReviewReport = {
  schema_version: 1;
  model: string;
  total_files: number;
  excluded_files: number;
  reviewed_files: string[];
  pending_files: FileResult[];
  findings: Finding[];
  coverage_gaps: string[];
  requests: number;
  estimated_tokens_reserved: number;
  reason: string | null;
};

function isReviewable(file: string) {
  return file.length <= 512 && sourceExtension.test(file) &&
    !file.split("/").some((part) => !part || part.startsWith(".") || /[\\:\u0000-\u001f]/.test(part));
}

async function readSource(root: string, file: string) {
  const path = await realpath(resolve(root, file));
  const rel = relative(root, path);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("source_unavailable");
  const info = await lstat(path);
  if (!info.isFile()) throw new Error("source_unavailable");
  if (info.size > maxFileBytes) throw new Error("file_size_limit");
  const bytes = await readFile(path);
  if (bytes.length > maxFileBytes) throw new Error("file_size_limit");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (text.includes("\0")) throw new Error("source_not_text");
  return text.split(/\r\n|\n|\r/);
}

function* chunks(lines: string[], limit: number) {
  let first = 0;
  let size = 0;
  for (let index = 0; index < lines.length; index++) {
    const length = Buffer.byteLength(JSON.stringify(lines[index])) + 1;
    if (length > limit) throw new Error("line_size_limit");
    if (size + length > limit) {
      yield { firstLine: first + 1, lines: lines.slice(first, index) };
      first = index;
      size = 0;
    }
    size += length;
  }
  yield { firstLine: first + 1, lines: lines.slice(first) };
}

export async function reviewProjectSource(
  input: { root: string; files: string[]; staticReport: ScannerReport },
  model: ReviewModel,
  controls: {
    cancelled: () => Promise<boolean>;
    checkpoint: (report: ProjectReviewReport) => Promise<void>;
    recordFailure?: (failure: ModelAttemptFailure) => Promise<void>;
    budget?: typeof projectReviewBudget;
    clock?: { now: () => number; wait: (milliseconds: number) => Promise<void> };
  },
) {
  const budget = controls.budget ?? projectReviewBudget;
  const clock = controls.clock ?? { now: Date.now, wait: delay };
  const deadline = clock.now() + budget.durationMs;
  const signal = AbortSignal.timeout(budget.durationMs);
  const root = await realpath(input.root);
  const allFiles = input.files.filter(isReviewable);
  const hints = new Map<string, ScannerReport["findings"]>();
  for (const finding of input.staticReport.findings) {
    if (!finding.file) continue;
    const existing = hints.get(finding.file) ?? [];
    existing.push(finding);
    hints.set(finding.file, existing);
  }
  const dependencyHints = input.staticReport.findings
    .filter((finding) => finding.tool === "trivy" && finding.type === "vulnerability" && finding.rule)
    .slice(0, 3)
    .map(({ id, severity, rule }) => ({ id, severity, rule }));
  // Inventory determines coverage. Findings don't control which files are eligible.
  const pending = new Map(allFiles.map((file) => [file, "not_started"]));
  const report: ProjectReviewReport = {
    schema_version: 1, model: model.name, total_files: allFiles.length,
    excluded_files: input.files.length - allFiles.length, reviewed_files: [], pending_files: [],
    findings: [], coverage_gaps: [], requests: 0, estimated_tokens_reserved: 0, reason: null,
  };
  const spend: { time: number; tokens: number }[] = [];
  const findingKeys = new Set<string>();
  function refresh() {
    report.pending_files = [...pending].map(([file, reason]) => ({ file, reason }));
    return report;
  }
  await controls.checkpoint(refresh());

  async function reserve(tokens: number) {
    while (true) {
      if (await controls.cancelled()) return "cancelled";
      const now = clock.now();
      if (now >= deadline) return "time_budget";
      if (report.requests >= budget.requests) return "request_budget";
      if (report.estimated_tokens_reserved + tokens > budget.estimatedTokens) return "token_budget";
      while (spend.length && now - spend[0].time >= 60_000) spend.shift();
      if (spend.reduce((sum, item) => sum + item.tokens, tokens) <= minuteTokens) {
        spend.push({ time: now, tokens });
        report.requests++;
        report.estimated_tokens_reserved += tokens;
        return null;
      }
      await clock.wait(Math.min(1000, deadline - now));
    }
  }

  async function pause(milliseconds: number) {
    const until = clock.now() + milliseconds;
    while (clock.now() < until) {
      if (await controls.cancelled()) return "cancelled";
      const now = clock.now();
      if (now >= deadline) return "time_budget";
      await clock.wait(Math.min(1000, Math.max(1, until - now), deadline - now));
    }
    return null;
  }

  async function askModel(payload: string, tokens: number) {
    for (let attempt = 1; attempt <= maxReviewAttempts; attempt++) {
      const stop = await reserve(tokens);
      if (stop) return { stop, problem: null, data: null };
      await controls.checkpoint(refresh());
      const cancellation = new AbortController();
      const poll = setInterval(() => {
        void controls.cancelled().then((stopped) => {
          if (stopped) cancellation.abort();
        }).catch(() => undefined);
      }, 1000);
      let failure: ReviewModelRequestError | null = null;
      try {
        const raw = await model.review(payload, AbortSignal.any([signal, cancellation.signal]));
        const parsed = modelReviewSchema.safeParse(raw);
        if (parsed.success) return { stop: null, problem: null, data: parsed.data };
        failure = new ReviewModelRequestError("model_invalid_response");
      } catch (error) {
        if (cancellation.signal.aborted) return { stop: "cancelled", problem: null, data: null };
        if (signal.aborted) return { stop: "time_budget", problem: null, data: null };
        failure = error instanceof ReviewModelRequestError ? error : new ReviewModelRequestError("model_network_error");
      } finally {
        clearInterval(poll);
      }
      const reason = failure.reason;
      const batchProblem = reason === "model_invalid_response" || reason === "model_response_truncated" || reason === "model_response_rejected";
      const retryable = failure.httpStatus === 400 ||
        (reason !== "model_authentication_failed" && reason !== "model_request_rejected" && reason !== "model_response_rejected");
      const retry = retryable && attempt < maxReviewAttempts &&
        report.requests < budget.requests && report.estimated_tokens_reserved + tokens <= budget.estimatedTokens;
      await controls.recordFailure?.({
        attempt, request_number: report.requests, reason,
        http_status: failure.httpStatus ?? null, provider_error_code: failure.providerErrorCode ?? null, retry_scheduled: retry,
      });
      if (!retry) {
        if (retryable && attempt < maxReviewAttempts) {
          const limit = report.requests >= budget.requests ? "request_budget" : "token_budget";
          return { stop: limit, problem: reason, data: null };
        }
        return { stop: batchProblem ? null : reason, problem: batchProblem ? reason : null, data: null };
      }
      const interrupted = await pause(reviewBackoffMs(attempt, failure.retryAfterMs));
      if (interrupted) return { stop: interrupted, problem: null, data: null };
    }
    throw new Error("review_attempt_state_invalid");
  }

  for (const file of allFiles) {
    if (await controls.cancelled()) { report.reason = "cancelled"; break; }
    if (clock.now() >= deadline) { report.reason = "time_budget"; break; }
    if (report.requests >= budget.requests) { report.reason = "request_budget"; break; }
    let lines: string[];
    try {
      lines = await readSource(root, file);
    } catch (error) {
      const reason = error instanceof Error && error.message === "file_size_limit" ? error.message : "source_unavailable";
      pending.set(file, reason);
      continue;
    }
    const staticFindings = hints.get(file) ?? [];
    const encode = (firstLine: number, sourceLines: string[]) => JSON.stringify({
      first_pass: {
        coverage: input.staticReport.tools.every((tool) => tool.status === "completed") &&
          input.staticReport.intake_gap_codes.length === 0 ? "complete" : "incomplete",
        tools: input.staticReport.tools,
        finding_count: input.staticReport.finding_count,
        dependency_findings: dependencyHints,
        related_findings: staticFindings.slice(0, 4).map(({ id, line, severity, rule }) => ({ id, line, severity, rule })),
      },
      sources: [{ file, first_line: firstLine, lines: sourceLines }],
    });
    let complete = true;
    try {
      for (const batch of chunks(lines, maxPayloadBytes - Buffer.byteLength(encode(1, [])) - 32)) {
        const payload = encode(batch.firstLine, batch.lines);
        const result = await askModel(payload, Buffer.byteLength(payload) + promptOverhead + outputTokens);
        if (!result.data) {
          if (result.stop) report.reason = result.stop;
          if (result.problem) pending.set(file, result.problem);
          complete = false;
          break;
        }
        for (const finding of result.data.findings) {
          const evidence = finding.file === file && batch.lines[finding.line - batch.firstLine]?.trim();
          if (!evidence) { pending.set(file, "invalid_model_citation"); complete = false; continue; }
          const key = JSON.stringify([file, finding.line, finding.title]);
          if (findingKeys.has(key)) continue;
          findingKeys.add(key);
          report.findings.push({
            ...finding, evidence: evidence.slice(0, 500),
            related_static_finding_ids: staticFindings.filter((hint) => hint.line === finding.line).slice(0, 10).map((hint) => hint.id),
          });
        }
        for (const gap of result.data.coverage_gaps) {
          if (report.coverage_gaps.length < 50) report.coverage_gaps.push(`${file}: ${gap}`);
        }
        pending.set(file, complete ? "partially_reviewed" : "invalid_model_citation");
      }
    } catch (error) {
      if (!(error instanceof Error) || error.message !== "line_size_limit") throw error;
      pending.set(file, error.message);
      complete = false;
    }
    if (complete) { pending.delete(file); report.reviewed_files.push(file); }
    if (report.reason) break;
    await controls.checkpoint(refresh());
  }
  if (report.reason) {
    for (const [file, reason] of pending) {
      if (reason === "not_started" || reason === "partially_reviewed") pending.set(file, report.reason);
    }
  } else if (!report.total_files) report.reason = "no_supported_source_files";
  else if (pending.size) report.reason = "file_coverage_incomplete";
  return refresh();
}
