import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { reviewProjectSource } from "../dist/project-review.js";
import { createZipAssessmentSchema } from "../dist/validation.js";
import { ReviewModelRequestError } from "../dist/code-review.js";
import { groqReview } from "../dist/groq-review.js";
import { shouldRetryDependencyScan } from "../dist/review-retry.js";

const assessmentId = "9e139a02-6a97-4549-9ba6-3ae06a367195";
const firstPass = {
  schema_version: 1, assessment_id: assessmentId, source_sha256: "a".repeat(64),
  tools: [
    { tool: "semgrep", status: "completed", findings: 0, failure_code: null },
    { tool: "trivy", status: "completed", findings: 0, failure_code: null },
  ],
  finding_count: 0, findings: [], intake_gap_codes: [],
};
const controls = {
  cancelled: async () => false,
  checkpoint: async () => {},
};

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "sapphire-project-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "src"));
  await writeFile(join(root, "src", "profile.ts"), "export function sendProfile(profile) {\n  return profile;\n}\n");
  await writeFile(join(root, "src", "other.ts"), "export const safe = true;\n");
  await mkdir(join(root, ".config"));
  await writeFile(join(root, ".config", "outside.ts"), "private fixture data");
  return { root, files: ["src/profile.ts", "src/other.ts", ".config/outside.ts", "package.json"] };
}

test("one submission explicitly opts in to sharing, and existing ZIP requests remain valid", () => {
  const base = { project_name: "example", target_url: "http://localhost:3000" };
  assert.equal(createZipAssessmentSchema.parse(base).ai_review_authorized, undefined);
  assert.equal(createZipAssessmentSchema.parse({ ...base, ai_review_authorized: "true" }).ai_review_authorized, true);
  assert.equal(createZipAssessmentSchema.safeParse({ project_name: "example", ai_review_authorized: "true" }).success, true);
  assert.equal(createZipAssessmentSchema.safeParse({ project_name: "example", ai_review_authorized: "true", runtime_discovery_authorized: "true" }).success, false);
  assert.equal(createZipAssessmentSchema.safeParse({ ...base, ai_review_authorized: "yes" }).success, false);
});

test("zero scanner findings still review every supported file and can surface a model-only finding", async t => {
  const input = await fixture(t);
  const modelFiles = [];
  const result = await reviewProjectSource({ ...input, staticReport: firstPass }, {
    name: "fixture",
    async review(payload) {
      const data = JSON.parse(payload);
      assert.equal(data.first_pass.finding_count, 0);
      assert.equal(data.first_pass.coverage, "complete");
      assert.deepEqual(data.first_pass.related_findings, []);
      assert.equal(data.sources.length, 1);
      const file = data.sources[0].file;
      modelFiles.push(file);
      return {
        findings: file === "src/profile.ts" ? [{
          file, line: 2, severity: "moderate", title: "Review profile field exposure",
          remediation: "Return only fields intended for the caller after applying authorization.",
        }] : [],
        coverage_gaps: [],
      };
    },
  }, controls);
  assert.deepEqual(modelFiles, ["src/profile.ts", "src/other.ts"]);
  assert.deepEqual(result.reviewed_files, modelFiles);
  assert.equal(result.excluded_files, 2);
  assert.deepEqual(result.pending_files, []);
  assert.equal(result.reason, null);
  assert.equal(result.findings[0].evidence, "return profile;");
  assert.deepEqual(result.findings[0].related_static_finding_ids, []);
});

test("an incomplete scanner pass still reaches the model, preserves context and reports the exhausted budget", async t => {
  const input = await fixture(t);
  const staticReport = {
    ...firstPass,
    tools: [{ tool: "semgrep", status: "failed", findings: 0, failure_code: "incomplete" }, firstPass.tools[1]],
    finding_count: 1,
    findings: [{ id: "advisory-1", tool: "trivy", type: "vulnerability", file: "package-lock.json", line: null, severity: "low", rule: "fixture-advisory" }],
  };
  const result = await reviewProjectSource({ ...input, staticReport }, {
    name: "fixture",
    async review(payload) {
      const data = JSON.parse(payload);
      assert.equal(data.first_pass.coverage, "incomplete");
      assert.equal(data.first_pass.dependency_findings[0].rule, "fixture-advisory");
      return { findings: [], coverage_gaps: [] };
    },
  }, { ...controls, budget: { requests: 1, estimatedTokens: 50_000, durationMs: 5000 } });
  assert.deepEqual(result.reviewed_files, ["src/profile.ts"]);
  assert.deepEqual(result.pending_files, [{ file: "src/other.ts", reason: "request_budget" }]);
  assert.equal(result.requests, 1);
  assert.equal(result.reason, "request_budget");
});

test("invalid citations cannot mark the file reviewed or attach another file as evidence", async t => {
  const input = await fixture(t);
  const result = await reviewProjectSource({ ...input, files: ["src/profile.ts"], staticReport: firstPass }, {
    name: "fixture",
    async review() {
      return { findings: [{ file: "src/other.ts", line: 1, severity: "high", title: "Unsupported", remediation: "Review." }], coverage_gaps: [] };
    },
  }, controls);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.reviewed_files, []);
  assert.deepEqual(result.pending_files, [{ file: "src/profile.ts", reason: "invalid_model_citation" }]);
});

function virtualClock() {
  let now = 0;
  return { now: () => now, async wait(ms) { now += ms; } };
}

test("Groq gets one initial attempt plus three retries with reserved budget and structured diagnostics", async t => {
  const input = await fixture(t);
  const clock = virtualClock();
  const events = [];
  const timestamps = [];
  const result = await reviewProjectSource({ ...input, files: ["src/profile.ts"], staticReport: firstPass }, {
    name: "fixture",
    async review() {
      timestamps.push(clock.now());
      if (timestamps.length === 1) throw new ReviewModelRequestError("model_rate_limited", 429, 7_000);
      if (timestamps.length <= 3) throw new ReviewModelRequestError("model_provider_unavailable", 503);
      return { findings: [], coverage_gaps: [] };
    },
  }, { ...controls, clock, async recordFailure(event) { events.push(event); } });
  assert.equal(result.reason, null);
  assert.equal(result.requests, 4);
  assert.ok(result.estimated_tokens_reserved > 4 * 2048);
  assert.ok(timestamps[1] - timestamps[0] >= 7_000);
  assert.deepEqual(events.map(event => [event.attempt, event.http_status, event.retry_scheduled]),
    [[1, 429, true], [2, 503, true], [3, 503, true]]);
});

test("when all four attempts fail, saved findings and uncovered files remain", async t => {
  const input = await fixture(t);
  const events = [];
  const result = await reviewProjectSource({ ...input, staticReport: firstPass }, {
    name: "fixture",
    async review(payload) {
      const file = JSON.parse(payload).sources[0].file;
      if (file === "src/other.ts") throw new ReviewModelRequestError("model_network_error");
      return { findings: [{ file, line: 2, severity: "low", title: "Review returned fields", remediation: "Minimize the exposed profile fields." }], coverage_gaps: [] };
    },
  }, { ...controls, clock: virtualClock(), async recordFailure(event) { events.push(event); } });
  assert.equal(result.requests, 5);
  assert.equal(result.reason, "model_network_error");
  assert.equal(result.findings[0].evidence, "return profile;");
  assert.deepEqual(result.reviewed_files, ["src/profile.ts"]);
  assert.deepEqual(result.pending_files, [{ file: "src/other.ts", reason: "model_network_error" }]);
  assert.deepEqual(events.map(event => event.retry_scheduled), [true, true, true, false]);
});

test("HTTP 400 retries three times and only the provider error code is audited", async t => {
  const input = await fixture(t);
  for (const recover of [true, false]) {
    let attempted = 0;
    const events = [];
    const model = groqReview("fixture", async () => {
      attempted++;
      if (recover && attempted === 4) {
        return Response.json({ choices: [{ finish_reason: "stop", message: { content: '{"findings":[],"coverage_gaps":[]}' } }] });
      }
      return Response.json({ error: {
        code: "json_validate_failed", message: "private-error-message", failed_generation: "private-response",
      } }, { status: 400 });
    });
    const report = await reviewProjectSource(
      { ...input, files: ["src/profile.ts"], staticReport: firstPass },
      model, { ...controls, clock: virtualClock(), async recordFailure(event) { events.push(event); } },
    );
    assert.equal(attempted, 4);
    assert.equal(report.requests, 4);
    assert.equal(report.reason, recover ? null : "file_coverage_incomplete");
    assert.equal(report.reviewed_files.length, recover ? 1 : 0);
    assert.deepEqual(events.map(event => [event.attempt, event.http_status, event.provider_error_code, event.retry_scheduled]),
      Array.from({ length: recover ? 3 : 4 }, (_, index) => [index + 1, 400, "json_validate_failed", index < 3]));
    assert.doesNotMatch(JSON.stringify({ events, report }), /private-error-message|private-response/);
  }
});

test("a truncated Groq batch is split with original line numbers and review continues", async t => {
  const input = await fixture(t);
  await writeFile(join(input.root, "src", "profile.ts"), Array.from({ length: 12 },
    (_, index) => `export const value${index + 1} = ${index + 1};`).join("\n"));
  const calls = [];
  const result = await reviewProjectSource({ ...input, staticReport: firstPass }, {
    name: "fixture",
    async review(payload) {
      const { file, first_line, lines } = JSON.parse(payload).sources[0];
      calls.push([file, first_line, lines.length]);
      if (lines.length === 12) throw new ReviewModelRequestError("model_request_rejected", 400, undefined, "json_validate_failed");
      return {
        findings: first_line === 7 ? [{
          file, line: 7, severity: "low", title: "Review this field",
          remediation: "Document its intended use.",
        }] : [],
        coverage_gaps: [],
      };
    },
  }, { ...controls, clock: virtualClock() });
  assert.deepEqual(calls, [["src/profile.ts", 1, 12], ["src/profile.ts", 1, 6],
    ["src/profile.ts", 7, 6], ["src/other.ts", 1, 2]]);
  assert.deepEqual(result.reviewed_files, ["src/profile.ts", "src/other.ts"]);
  assert.equal(result.findings[0].evidence, "export const value7 = 7;");
  assert.equal(result.reason, null);
});

test("persistent JSON validation failures do not stop later files", async t => {
  const input = await fixture(t);
  const result = await reviewProjectSource({ ...input, staticReport: firstPass }, {
    name: "fixture",
    async review(payload) {
      if (JSON.parse(payload).sources[0].file === "src/profile.ts") {
        throw new ReviewModelRequestError("model_request_rejected", 400, undefined, "json_validate_failed");
      }
      return { findings: [], coverage_gaps: [] };
    },
  }, { ...controls, clock: virtualClock() });
  assert.equal(result.requests, 5);
  assert.deepEqual(result.reviewed_files, ["src/other.ts"]);
  assert.deepEqual(result.pending_files, [{ file: "src/profile.ts", reason: "model_response_truncated" }]);
});

test("invalid credentials are logged once and exhausted malformed batches do not block other files", async t => {
  const input = await fixture(t);
  const events = [];
  const failed = await reviewProjectSource({ ...input, staticReport: firstPass }, {
    name: "fixture",
    async review() { throw new ReviewModelRequestError("model_authentication_failed", 401); },
  }, { ...controls, clock: virtualClock(), async recordFailure(event) { events.push(event); } });
  assert.equal(failed.requests, 1);
  assert.equal(failed.reason, "model_authentication_failed");
  assert.deepEqual(events.map(event => event.retry_scheduled), [false]);

  const partial = await reviewProjectSource({ ...input, staticReport: firstPass }, {
    name: "fixture",
    async review(payload) {
      if (JSON.parse(payload).sources[0].file === "src/profile.ts") {
        throw new ReviewModelRequestError("model_response_truncated");
      }
      return { findings: [], coverage_gaps: [] };
    },
  }, { ...controls, clock: virtualClock() });
  assert.equal(partial.requests, 5);
  assert.equal(partial.reason, "file_coverage_incomplete");
  assert.deepEqual(partial.reviewed_files, ["src/other.ts"]);
  assert.deepEqual(partial.pending_files, [{ file: "src/profile.ts", reason: "model_response_truncated" }]);
});

test("dependency attempts are bounded and never retry unsupported input, cancellation, or a missing database", () => {
  for (const attempt of [1, 2, 3]) assert.equal(shouldRetryDependencyScan("scanner_exit_nonzero", attempt), true);
  assert.equal(shouldRetryDependencyScan("scanner_exit_nonzero", 4), false);
  for (const reason of ["trivy_db_metadata_missing", "trivy_db_metadata_invalid", "invalid_zip_snapshot", "cancelled"]) {
    assert.equal(shouldRetryDependencyScan(reason, 1), false);
  }
});
