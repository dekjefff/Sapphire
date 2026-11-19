import assert from "node:assert/strict";
import { test } from "node:test";
import Fastify from "fastify";
import { registerPassiveEvidence } from "../dist/passive-evidence-api.js";
import { PassiveEvidenceCapture } from "../dist/passive-evidence.js";

const assessment = "11111111-1111-4111-8111-111111111111";
const otherAssessment = "22222222-2222-4222-8222-222222222222";
const page = "33333333-3333-4333-8333-333333333333";
const secret = "should-never-enter-the-report";
const key = Buffer.alloc(32, 7);
const entry = {
  startedDateTime: "2026-10-01T00:00:00.000Z",
  request: {
    method: "GET",
    url: `https://app.example/dashboard?token=${secret}`,
    headers: [{ name: "Authorization", value: `Bearer ${secret}` }],
    cookies: [{ name: "session", value: secret }],
  },
  response: { status: 200, content: { text: secret } },
};
const har = { log: { entries: [entry] } };

async function fixture(t, verificationKey) {
  const app = Fastify();
  const records = new Map();
  await app.register(async (scope) => registerPassiveEvidence(scope, {
    async put(assessmentId, record) {
      if (![assessment, otherAssessment].includes(assessmentId)) return "missing";
      const id = `${assessmentId}/${record.run_id}`;
      if (records.has(id) && JSON.stringify(records.get(id)) !== JSON.stringify(record)) return "conflict";
      records.set(id, structuredClone(record));
      return "saved";
    },
    async get(assessmentId, runId) {
      return records.get(`${assessmentId}/${runId}`) ?? null;
    },
    async latest(assessmentId) {
      return [...records.entries()].findLast(([id]) => id.startsWith(`${assessmentId}/`))?.[1] ?? null;
    },
  }, verificationKey));
  t.after(() => app.close());
  const route = (assessmentId = assessment) => `/assessments/${assessmentId}/passive-captures`;
  return { app, records, route };
}

test("stores a HAR-only import as unverified and unknown without retaining HAR", async (t) => {
  const { app, records, route } = await fixture(t);
  assert.equal((await app.inject(`${route()}/latest`)).json(), null);
  const result = await app.inject({ method: "POST", url: route(), payload: { har } });
  assert.equal(result.statusCode, 201, result.body);
  const record = result.json();
  assert.equal(record.authentication, "unverified");
  assert.equal(record.coverage, "unknown");
  assert.equal("har" in record, false);
  assert.equal(JSON.stringify([...records.values()]).includes(secret), false);
  const fetched = await app.inject(`${route()}/${record.run_id}`);
  assert.equal(fetched.statusCode, 200);
  assert.deepEqual(fetched.json(), record);
  assert.deepEqual((await app.inject(`${route()}/latest`)).json(), record);
  assert.equal((await app.inject(`${route(otherAssessment)}/${record.run_id}`)).statusCode, 404);
});

test("rejects unconfigured signed import and strips parsing errors", async (t) => {
  const { app, records, route } = await fixture(t);
  const signed = await app.inject({ method: "POST", url: route(), payload: { har, manifest: {}, signature: "invalid" } });
  assert.equal(signed.statusCode, 503);
  const invalid = await app.inject({
    method: "POST", url: route(), headers: { "content-type": "application/json" },
    payload: `{"har":${secret}}`,
  });
  assert.equal(invalid.statusCode, 400);
  assert.equal(invalid.body.includes(secret), false);
  assert.equal(records.size, 0);
});

test("persists signed evidence, rejects altered payloads and prevents cross-assessment replay", async (t) => {
  const { app, records, route } = await fixture(t, key);
  const firstParty = Fastify();
  t.after(() => firstParty.close());
  const session = `session=${secret}`;
  const sessions = new Map([[session, "user"]]);
  firstParty.get("/dashboard", (request, reply) => {
    if (!sessions.has(request.headers.cookie)) return reply.code(401).send();
    return { dashboard: true };
  });
  const runtime = new PassiveEvidenceCapture(assessment, [{ id: page, kind: "page" }]);
  await runtime.start(() => {
    const role = sessions.get(session);
    return role ? { state: "authenticated", method: "server_session", role } :
      { state: "anonymous", method: "server_session" };
  });
  const startedDateTime = new Date().toISOString();
  const response = await firstParty.inject({ url: "/dashboard", headers: { cookie: session } });
  assert.equal(response.statusCode, 200);
  const observed = { ...entry, startedDateTime, response: { ...entry.response, status: response.statusCode } };
  const currentHar = { log: { entries: [observed] } };
  runtime.observeRequest(observed);
  runtime.recordItem(page, "observed", { first: 1, last: 1 });
  const signed = runtime.finish(currentHar, key);
  const post = (url, payload) => app.inject({ method: "POST", url, payload });
  assert.equal((await post(route(otherAssessment), signed)).statusCode, 422);
  const changed = structuredClone(signed);
  changed.har.log.entries[0].response.status = 403;
  assert.equal((await post(route(), changed)).statusCode, 422);
  const wrongUrl = structuredClone(currentHar);
  wrongUrl.log.entries[0].request.url = "https://app.example/settings";
  assert.equal((await post(route(), { ...signed, har: wrongUrl })).statusCode, 422);
  assert.equal(records.size, 0);
  const accepted = await post(route(), { ...signed, har: currentHar });
  assert.equal(accepted.statusCode, 201, accepted.body);
  assert.equal(accepted.json().authentication, "verified");
  assert.equal(accepted.json().session.role, "user");
  assert.equal(accepted.json().coverage, "known");
  assert.equal(JSON.stringify([...records.values()]).includes(secret), false);
  assert.deepEqual((await app.inject(`${route()}/${accepted.json().run_id}`)).json(), accepted.json());
  assert.equal((await post(route(), signed)).statusCode, 201);
  assert.equal(records.size, 1);
});
