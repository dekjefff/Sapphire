import test from "node:test";
import assert from "node:assert/strict";
import { PassiveEvidenceCapture, importPassiveEvidence } from "../dist/passive-evidence.js";
const scope = "7d8ad44a-4594-42dc-af19-4d1e98f95e73", page = "6d8ad44a-4594-42dc-af19-4d1e98f95e73", step = "5d8ad44a-4594-42dc-af19-4d1e98f95e73", flow = "4d8ad44a-4594-42dc-af19-4d1e98f95e73";
const key = Buffer.alloc(32, 7);
const exchange = { startedDateTime: "2026-11-19T08:00:00Z", request: { method: "GET", url: "https://user:secret@example.test/?token=secret", headers: [{ name: "Authorization", value: "secret" }] }, response: { status: 200, content: { text: "secret" }, cookies: [{ value: "secret" }] } };
const recordedExchange = capture => ({ ...exchange, startedDateTime: capture.progress().manifest.started_at });
const harFrom = entry => ({ log: { entries: [entry] } });
test("trusted runtime signs sanitized ordered evidence with flow gaps", async () => {
  const capture = new PassiveEvidenceCapture(scope, [{ id: page, kind: "page", label: "/dashboard" }, { id: step, kind: "flow_step", flow_id: flow, label: "View item details" }]);
  assert.equal(capture.progress().manifest.status, "queued");
  let checked = 0; await capture.start(async () => { checked++; return { state: "authenticated", method: "server_session", role: "user" }; });
  const entry = recordedExchange(capture);
  assert.equal(checked, 1); capture.observeRequest(entry); capture.recordItem(page, "observed", { first: 1, last: 1 }); capture.recordItem(step, "skipped", undefined, "not_reached");
  const bundle = capture.finish(harFrom(entry), key); const result = importPassiveEvidence(bundle, key);
  assert.equal(result.authentication, "verified"); assert.equal(result.session.state, "authenticated"); assert.equal(result.coverage, "known");
  assert.deepEqual(result.counts, { expected: 2, observed: 1, failed: 0, skipped: 1, pending: 0, processed: 2, remaining: 0, uncovered: 1, requests: 1 });
  assert.equal(result.gaps[0].flow_id, flow); assert.equal(result.gaps[0].label, "View item details"); assert.equal(result.observed[0].id, page);
  assert.equal(result.manifest.session.first_request, 1); assert.equal(result.manifest.session.last_request, 1); assert.ok(result.manifest.session.checked_at);
  assert.ok(!JSON.stringify(result).includes("secret")); assert.equal(capture.progress().manifest.status, "completed");
  assert.deepEqual(result.manifest.events.map(e => e.status), ["queued", "running", "running", "running", "running", "completed"]);
  assert.deepEqual(result.manifest.events.map(e => e.counts.requests), [0, 0, 1, 1, 1, 1]);
  assert.ok(result.manifest.events.every(event => event.run_id === result.manifest.run_id));
});
test("unsigned, asserted, altered, and legacy input cannot upgrade claims", async () => {
  const capture = new PassiveEvidenceCapture(scope, []); await capture.start(() => ({ state: "anonymous", method: "application_session" }));
  const entry = recordedExchange(capture);
  const har = harFrom(entry);
  capture.observeRequest(entry);
  const bundle = capture.finish(har, key);
  for (const input of [{ har }, { ...bundle, signature: "0".repeat(64) }, { ...bundle, har: { log: { entries: [{ ...exchange, startedDateTime: "2026-11-19T08:00:01Z" }] } } }, { ...bundle, manifest: { ...bundle.manifest, scope_id: page } }]) {
    const result = importPassiveEvidence(input, key); assert.equal(result.authentication, "unverified"); assert.equal(result.coverage, "unknown"); assert.ok(!JSON.stringify(result).includes("secret"));
  }
  assert.equal(importPassiveEvidence({ har, assertion: "authenticated" }, key).authentication, "asserted");
  assert.equal(importPassiveEvidence(bundle, key).session.state, "anonymous"); assert.equal(importPassiveEvidence(bundle, key).coverage, "unknown");
});
test("lifecycle rejects invalid input and leaves failed coverage gaps", async () => {
  const capture = new PassiveEvidenceCapture(scope, [{ id: page, kind: "page" }]);
  assert.throws(() => capture.observeRequest(exchange));
  await capture.start(() => ({ state: "anonymous", method: "server_session" }));
  assert.throws(() => capture.recordItem(page, "observed", { first: 1, last: 1 }));
  assert.throws(() => capture.observeRequest({ ...exchange, startedDateTime: "2020-01-01T00:00:00Z" }), /outside the capture session window/);
  const entry = recordedExchange(capture);
  capture.observeRequest(entry);
  assert.throws(() => capture.finish({ log: { entries: [{ ...exchange, startedDateTime: "2026-11-19T08:00:01Z" }] } }, key));
  const bundle = capture.finish(harFrom(entry), key, true); const result = importPassiveEvidence(bundle, key);
  assert.equal(bundle.manifest.status, "failed"); assert.equal(result.gaps[0].status, "pending");
  assert.equal(result.coverage, "unknown");
  assert.equal(bundle.manifest.events.at(-1).error, "collection_failed");
});
test("empty session range is null, and safe error codes cannot contain arbitrary text", async () => {
  const capture = new PassiveEvidenceCapture(scope, [{ id: page, kind: "page" }]); await capture.start(() => ({ state: "anonymous", method: "server_session" }));
  assert.throws(() => capture.recordItem(page, "failed", undefined, "secret"));
  capture.recordItem(page, "failed", undefined, "error");
  const bundle = capture.finish({ log: { entries: [] } }, key, true);
  assert.equal(bundle.manifest.session.first_request, null); assert.equal(bundle.manifest.session.last_request, null);
  assert.equal(importPassiveEvidence(bundle, key).counts.failed, 1);
});

test("session check failures preserve a safe terminal event with no verified state", async () => {
  const capture = new PassiveEvidenceCapture(scope, [{ id: page, kind: "page" }]);
  await assert.rejects(capture.start(async () => { throw new Error("secret"); }), /Passive capture session check failed/);
  const empty = { log: { entries: [] } };
  const result = importPassiveEvidence(capture.finish(empty, key), key);
  assert.equal(result.authentication, "unverified");
  assert.equal(result.coverage, "unknown");
  assert.equal(result.manifest.status, "failed");
  assert.equal(result.manifest.events.at(-1).error, "session_check_failed");
  assert.equal(JSON.stringify(result).includes("secret"), false);
});
