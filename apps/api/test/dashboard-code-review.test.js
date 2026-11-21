import assert from "node:assert/strict";
import test from "node:test";
import Fastify from "fastify";
import { registerDashboardCodeReview } from "../dist/dashboard-code-review.js";

const origin = "http://localhost:3000";
const assessment = "9e139a02-6a97-4549-9ba6-3ae06a367195";
const url = `/assessments/${assessment}/ai-code-review`;
const request = {
  share_with_providers: true,
  manifest: "{}",
  lockfile: "{}",
  sources: [{ name: "review.ts", text: "export const enabled = true;" }],
};
const report = {
  schema_version: 1,
  status: "reviewed",
  model: "groq:fixture",
  dependency_audit: {
    status: "clean", lockfile_verified: true, finding_count: 0,
  },
  reviewed_files: ["review.ts"],
  findings: [],
  coverage_gaps: [],
};

function fixture(t, run) {
  const app = Fastify();
  t.after(() => app.close());
  const saved = new Map();
  registerDashboardCodeReview(app, {
    origins: [origin],
    run,
    store: {
      async exists(id) { return id === assessment; },
      async latest(id) { return saved.get(id) ?? null; },
      async save(id, result) {
        const entry = { report: result, created_at: "2026-11-20T00:00:00.000Z" };
        saved.set(id, entry);
        return entry;
      },
    },
  });
  return app;
}

test("a dashboard review stores the report under the chosen assessment", async t => {
  const app = fixture(t, async payload => {
    assert.deepEqual(payload.sources, request.sources);
    return report;
  });
  const headers = { origin };
  assert.equal((await app.inject({ method: "GET", url, headers })).statusCode, 404);
  const result = await app.inject({ method: "POST", url, headers, payload: request });
  assert.equal(result.statusCode, 201);
  assert.deepEqual(result.json().report, report);
  const latest = await app.inject({ method: "GET", url, headers });
  assert.equal(latest.statusCode, 200);
  assert.equal(latest.headers["cache-control"], "no-store");
  assert.deepEqual(latest.json(), result.json());
});

test("rejects unapproved sharing, unsafe paths and untrusted origins before reviewing", async t => {
  let calls = 0;
  const app = fixture(t, async () => { calls++; return report; });
  for (const [headers, payload, expected] of [
    [{ origin: "https://example.test" }, request, 403],
    [{ origin }, { ...request, share_with_providers: false }, 422],
    [{ origin }, { ...request, sources: [{ name: "../review.ts", text: "source" }] }, 422],
    [{ origin }, { ...request, sources: [{ name: "NUL.ts", text: "source" }] }, 422],
  ]) {
    assert.equal((await app.inject({ method: "POST", url, headers, payload })).statusCode, expected);
  }
  const unknown = "/assessments/0e139a02-6a97-4549-9ba6-3ae06a367195/ai-code-review";
  assert.equal((await app.inject({ method: "POST", url: unknown, headers: { origin }, payload: request })).statusCode, 404);
  assert.equal((await app.inject({ method: "GET", url })).statusCode, 403);
  assert.equal(calls, 0);
});

test("reports unavailable configuration and prevents overlapping dashboard reviews", async t => {
  const headers = { origin };
  const disabled = fixture(t);
  assert.equal((await disabled.inject({ method: "POST", url, headers, payload: request })).statusCode, 503);
  let started;
  let finish;
  const waiting = new Promise(resolve => { started = resolve; });
  const completion = new Promise(resolve => { finish = resolve; });
  const app = fixture(t, async () => { started(); return completion; });
  const first = app.inject({ method: "POST", url, headers, payload: request });
  try {
    await waiting;
    assert.equal((await app.inject({ method: "POST", url, headers, payload: request })).statusCode, 409);
  } finally {
    finish(report);
  }
  assert.equal((await first).statusCode, 201);
});
