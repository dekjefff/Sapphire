import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { reviewProjectSource } from "../dist/project-review.js";
import { createZipAssessmentSchema } from "../dist/validation.js";

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
