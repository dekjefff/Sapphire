import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { modelReviewSchema, ReviewModelRequestError, type ReviewModel } from "./code-review.js";

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
    budget?: typeof projectReviewBudget;
  },
) {
  const budget = controls.budget ?? projectReviewBudget;
  const deadline = Date.now() + budget.durationMs;
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
      const now = Date.now();
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
      await delay(Math.min(1000, deadline - now));
    }
  }

  for (const file of allFiles) {
    if (await controls.cancelled()) { report.reason = "cancelled"; break; }
    if (Date.now() >= deadline) { report.reason = "time_budget"; break; }
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
        const stop = await reserve(Buffer.byteLength(payload) + promptOverhead + outputTokens);
        if (stop) { report.reason = stop; complete = false; break; }
        await controls.checkpoint(refresh());
        const cancellation = new AbortController();
        const poll = setInterval(() => {
          void controls.cancelled().then((stopped) => {
            if (stopped) cancellation.abort();
          }).catch(() => undefined);
        }, 1000);
        let raw: unknown;
        try {
          raw = await model.review(payload, AbortSignal.any([signal, cancellation.signal]));
        } catch (error) {
          report.reason = cancellation.signal.aborted ? "cancelled" : signal.aborted ? "time_budget" :
            error instanceof ReviewModelRequestError ? error.reason : "model_request_failed";
          complete = false;
          break;
        } finally {
          clearInterval(poll);
        }
        const parsed = modelReviewSchema.safeParse(raw);
        if (!parsed.success) { pending.set(file, "invalid_model_report"); complete = false; break; }
        for (const finding of parsed.data.findings) {
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
        for (const gap of parsed.data.coverage_gaps) {
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
