import test, { after } from "node:test";
import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const tempDirs = [];
let matching, validation, profiles, summary, scopePolicy;
try {
  const paths = [
    resolve(root, "apps/api/dist/discovery/matching.js"), resolve(root, "apps/api/dist/validation.js"),
    resolve(root, "apps/api/dist/discovery/authorization-profiles.js"), resolve(root, "apps/api/dist/discovery/assessment-summary.js"),
    resolve(root, "apps/api/dist/discovery-scope-policy.js"),
  ];
  await Promise.all(paths.map(access));
  [matching, validation, profiles, summary, scopePolicy] = await Promise.all(paths.map(path => import(pathToFileURL(path))));
} catch { /* a missing build is reported as a test skip */ }
after(async () => Promise.all(tempDirs.map(path => rm(path, { recursive: true, force: true }))));

function available(t) {
  if (matching && validation && profiles && summary && scopePolicy) return true;
  t.skip("WP6 API dist modules unavailable; run npm --prefix apps/api run build"); return false;
}

test("WP6 canonical route matching handles repeated/trailing slashes, query and fragment", t => {
  if (!available(t)) return;
  assert.equal(matching.normalizeRoutePath("///users//alice///?token=secret#fragment"), "/users/alice");
  const [row] = matching.planRouteMatches(
    [{ id: "700000000000000001", method: "GET", path: "/users/:name/", source_file: "src/routes.ts", source_line: 4 }],
    [{ id: "9007199254740995", method: "GET", path: "//users//alice///?debug=secret#frag" }],
  );
  assert.equal(row.coverage_class, "matched"); assert.equal(row.runtime_endpoint_id, "9007199254740995");
  assert.equal(row.source_route_id, "700000000000000001"); assert.equal(row.source_route, "/users/:name");
});

test("WP6 colon/bracket parameters match one segment and catch-all accepts multiple segments", t => {
  if (!available(t)) return;
  const source = [
    { id: "1", method: "GET", path: "/users/:userId", source_file: "src/users.ts", source_line: 1 },
    { id: "2", method: "GET", path: "/docs/[slug]", source_file: "src/docs.ts", source_line: 2 },
    { id: "3", method: "GET", path: "/files/[...rest]", source_file: "src/files.ts", source_line: 3 },
  ];
  const rows = matching.planRouteMatches(source, [
    { id: "101", method: "GET", path: "/users/alice" }, { id: "102", method: "GET", path: "/users/alice/profile" },
    { id: "103", method: "GET", path: "/docs/intro" }, { id: "104", method: "GET", path: "/docs/intro/extra" },
    { id: "105", method: "GET", path: "/files/a/b/c" },
  ]);
  assert.deepEqual(rows.slice(0, 5).map(row => row.coverage_class), ["matched", "runtime_only", "matched", "runtime_only", "matched"]);
  assert.equal(rows.find(row => row.runtime_endpoint_id === "105").source_route_id, "3");
});

test("WP6 literal segments compare exactly and method mismatches do not match", t => {
  if (!available(t)) return;
  const rows = matching.planRouteMatches(
    [{ id: "1", method: "GET", path: "/users/me", source_file: "src/routes.ts", source_line: 1 }, { id: "2", method: "POST", path: "/users/:name", source_file: "src/routes.ts", source_line: 2 }],
    [{ id: "11", method: "GET", path: "/users/me" }, { id: "12", method: "GET", path: "/users/men" }, { id: "13", method: "POST", path: "/users/me" }],
  );
  assert.equal(rows[0].coverage_class, "matched"); assert.equal(rows[1].coverage_class, "runtime_only");
  assert.equal(rows.some(row => row.runtime_endpoint_id === "13"), false);
  assert.equal(rows.some(row => row.source_route_id === "2"), false, "non-GET source routes are excluded from discovery comparisons");
});

test("WP6 ambiguous candidates remain unresolved and BIGSERIAL IDs stay strings", t => {
  if (!available(t)) return;
  const rows = matching.planRouteMatches(
    [{ id: "9007199254740993", method: "GET", path: "/users/:name", source_file: "a.ts", source_line: 1 }, { id: "9007199254740994", method: "GET", path: "/users/[slug]", source_file: "b.ts", source_line: 2 }],
    [{ id: "9007199254740995", method: "GET", path: "/users/alice" }],
  );
  assert.equal(rows[0].coverage_class, "unresolved"); assert.equal(rows[0].runtime_endpoint_id, "9007199254740995");
  assert.deepEqual(rows[0].candidate_source_route_ids, ["9007199254740993", "9007199254740994"]);
  assert.equal(typeof rows[0].candidate_source_route_ids[0], "string"); assert.equal(rows[0].reason_code, "unresolved_route");
});

test("WP6 matching emits matched, source-only and runtime-only classes", t => {
  if (!available(t)) return;
  const rows = matching.planRouteMatches(
    [{ id: "1", method: "GET", path: "/present", source_file: "src/a.ts", source_line: 8 }, { id: "2", method: "GET", path: "/not-seen", source_file: "src/b.ts", source_line: 9 }],
    [{ id: "10", method: "GET", path: "/present" }, { id: "11", method: "GET", path: "/unlisted" }],
  );
  assert.deepEqual(rows.map(row => row.coverage_class), ["matched", "runtime_only", "source_only"]);
});

test("WP6 refresh is logically idempotent and preserves safe raw-pointer provenance", async t => {
  if (!available(t)) return;
  const assessmentId = "10000000-0000-4000-8000-000000000001", endpointId = "9007199254740995";
  const sourceRows = [
    { id: "9007199254740993", method: "GET", path: "/api/items/:id", source_file: "C:\\private\\repo\\route.ts", source_line: "7" },
    { id: "9007199254740994", method: "GET", path: "/api/not-seen", source_file: "/private/repo/other.ts", source_line: "9" },
  ];
  const endpointRows = [{ id: endpointId, tool_run_id: "9007199254740996", artifact_id: "9007199254740997", method: "GET", path: "/api/items/42?secret=yes", scope_policy_sha256: "a".repeat(64), raw_pointers: { [endpointId]: "/line/4" } }];
  const inserts = [];
  const client = { inserts, async query(sql, values) {
    if (sql.startsWith("SELECT id,method,path,source_file")) return { rows: sourceRows };
    if (sql.startsWith("SELECT e.id")) return { rows: endpointRows };
    if (sql.startsWith("DELETE")) return { rows: [] };
    if (sql.startsWith("INSERT INTO endpoint_route_matches")) { inserts.push(values); return { rows: [] }; }
    throw new Error(`unexpected SQL: ${sql}`);
  } };
  await matching.refreshRouteMatches(client, assessmentId);
  const first = inserts.splice(0);
  await matching.refreshRouteMatches(client, assessmentId);
  const second = inserts.splice(0);
  assert.deepEqual(first.map(values => values.slice(1, 10)), second.map(values => values.slice(1, 10)));
  const matched = first.find(values => values[3] === "matched"), evidence = JSON.parse(matched[10]);
  assert.equal(matched[6], null, "absolute source host paths must be omitted");
  assert.equal(evidence.raw_pointer, "/line/4"); assert.equal(evidence.tool_run_id, "9007199254740996");
  assert.equal(evidence.artifact_id, "9007199254740997");
  assert.ok(!JSON.stringify(first).includes("private")); assert.ok(!JSON.stringify(first).includes("secret=yes"));
});

test("WP6 assessment summary resolves complete, incomplete, failed, cancelled, empty, pending and not-authorized states", t => {
  if (!available(t)) return;
  const resolveState = summary.resolveDiscoveryState;
  assert.equal(resolveState([{ status: "completed", coverage_status: "complete" }], 1, 1), "complete");
  assert.equal(resolveState([{ status: "completed", coverage_status: "incomplete" }], 1, 1), "incomplete");
  assert.equal(resolveState([{ status: "failed", coverage_status: "incomplete" }, { status: "cancelled", coverage_status: "incomplete" }], 0, 1), "failed");
  assert.equal(resolveState([{ status: "cancelled", coverage_status: "incomplete" }, { status: "running", coverage_status: "pending" }], 0, 1), "cancelled");
  assert.equal(resolveState([{ status: "running", coverage_status: "pending" }, { status: "completed", coverage_status: "incomplete" }], 0, 1), "running");
  assert.equal(resolveState([{ status: "completed", coverage_status: "complete" }], 0, 1), "empty");
  assert.equal(resolveState([], 0, 1), "pending"); assert.equal(resolveState([], 0, 0), "not_authorized");
});

test("WP6 pagination schema applies defaults and hard bounds", t => {
  if (!available(t)) return;
  assert.deepEqual(validation.assessmentDetailQuerySchema.parse({}), { limit: 50, endpoint_cursor: 0, match_cursor: 0 });
  assert.equal(validation.assessmentDetailQuerySchema.safeParse({ limit: "1", endpoint_cursor: "1000000", match_cursor: "0" }).success, true);
  for (const query of [{ limit: 0 }, { limit: 101 }, { endpoint_cursor: -1 }, { endpoint_cursor: 1_000_001 }, { match_cursor: "NaN" }, { extra: "no" }]) assert.equal(validation.assessmentDetailQuerySchema.safeParse(query).success, false, JSON.stringify(query));
});

test("WP7 multipart form contract and budget DTO expose only approved fields", async t => {
  if (!available(t)) return;
  assert.equal(validation.createZipAssessmentSchema.safeParse({ project_name: "demo", target_url: "http://juiceshop:3000", runtime_discovery_authorized: "true" }).success, true);
  assert.equal(validation.createZipAssessmentSchema.safeParse({ project_name: "demo", target_url: "http://juiceshop:3000", runtime_discovery_authorized: "yes" }).success, false);
  assert.equal(validation.createZipAssessmentSchema.safeParse({ project_name: "demo", target_url: "http://juiceshop:3000", pinned_ips: ["1.2.3.4"] }).success, false);
  const budgetModule = await import(pathToFileURL(resolve(root, "apps/api/dist/discovery/assessment-summary.js")));
  const budget = budgetModule.getDiscoveryBudgetDto();
  assert.deepEqual(Object.keys(budget).sort(), ["profile_id", "crawl_depth", "unique_urls", "global_concurrency", "per_host_concurrency", "requests_per_second", "per_host_requests_per_second", "connect_timeout_seconds", "request_timeout_seconds", "retries", "max_response_bytes", "total_response_bytes", "wall_clock_seconds"].sort());
  assert.equal(budget.profile_id, "discovery-default-v1"); assert.equal(budget.retries, 0);
  const api = await readFile(resolve(root, "apps/api/src/server.ts"), "utf8");
  assert.match(api, /limits:\s*\{\s*files:\s*1,\s*fileSize:\s*100\s*\*\s*1024\s*\*\s*1024,\s*fields:\s*3,\s*parts:\s*4\s*\}/);
  const webApi = await readFile(resolve(root, "apps/web/lib/api.ts"), "utf8");
  assert.match(webApi, /body\.append\('runtime_discovery_authorized', String\(input\.runtime_discovery_authorized\)\)/);
  assert.match(webApi, /body\.append\('source', input\.source_file\)/);
});

test("WP6 operator allowlist requires exact canonical origins and a valid Juice Shop profile", t => {
  if (!available(t)) return;
  const old = process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON;
  try {
    process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = JSON.stringify([{ origin: "https://staging.example", pinned_ips: ["203.0.113.10"], policy_revision: "staging-v1" }]);
    assert.equal(profiles.findDiscoveryProfile("https://staging.example")?.policy_revision, "staging-v1");
    assert.equal(profiles.findDiscoveryProfile("https://staging.example:443"), null); assert.equal(profiles.findDiscoveryProfile("https://other.example"), null);
    for (const origin of ["https://*.example", "https://user@staging.example", "https://staging.example?x=1", "https://staging.example#frag", "https://staging.example/"]) {
      process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = JSON.stringify([{ origin, pinned_ips: ["203.0.113.10"] }]);
      assert.equal(profiles.findDiscoveryProfile(origin), null, origin);
    }
    process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = "not-json"; assert.equal(profiles.findDiscoveryProfile("https://staging.example"), null);
    process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = JSON.stringify([{ origin: "https://secure.example", pinned_ips: ["203.0.113.11"], path_mode: "prefix", path_prefixes: ["/api"] }]);
    assert.equal(profiles.findDiscoveryProfile("https://secure.example"), null, "HTTPS prefix scope must be rejected");
    process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = "[]";
    const juice = profiles.findDiscoveryProfile("http://juiceshop:3000");
    assert.deepEqual(juice, { origin: "http://juiceshop:3000", pinned_ips: ["172.31.80.10"], policy_revision: "juiceshop-local-v1", path_mode: "whole_origin", path_prefixes: [] });
    const scope = scopePolicy.createDiscoveryScope({ scope_id: "11111111-1111-4111-8111-111111111111", assessment_id: "22222222-2222-4222-8222-222222222222", origin: juice.origin, path_mode: juice.path_mode, path_prefixes: juice.path_prefixes, pinned_ips: juice.pinned_ips, policy_revision: juice.policy_revision, authorization_actor: "operator-test", authorized_at: "2026-01-01T00:00:00.000Z", expires_at: "2030-01-01T00:00:00.000Z" });
    assert.equal(scope.host, "juiceshop"); assert.deepEqual(scope.allowed_methods, ["GET"]);
  } finally {
    if (old === undefined) delete process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON; else process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = old;
  }
});

test("WP6 target validation and source guards preserve static-only, attested scope and safe response fields", async t => {
  if (!available(t)) return;
  const old = process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON, server = await readFile(resolve(root, "apps/api/src/server.ts"), "utf8");
  try {
    process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = JSON.stringify([{ origin: "https://staging.example", pinned_ips: ["203.0.113.10"] }]);
    assert.equal(validation.validateTarget("https://staging.example/project"), "https://staging.example/project");
    for (const target of ["https://staging.example/?secret=x", "https://staging.example/#secret", "https://user@staging.example/"]) assert.throws(() => validation.validateTarget(target));
    assert.equal(validation.validateTarget("http://juiceshop:3000/"), "http://juiceshop:3000/");
    assert.match(server, /if \(!attested\) return null/);
    assert.match(server, /if \(runtimeDiscoveryAuthorized && !scope\)[\s\S]*?reply\.code\(422\)/);
    assert.match(server, /runtime_discovery: \{ status: scope \? "authorized" : "not_authorized"/);
    const scopeSelect = server.match(/SELECT id,scheme,host,port,path_mode,path_prefixes,policy_revision,policy_sha256,authorized_at,expires_at FROM discovery_scopes/);
    assert.ok(scopeSelect, "scope detail projection must omit pinned IPs"); assert.ok(!scopeSelect[0].includes("pinned_ips"));
    assert.match(server, /CASE WHEN source_file !~ '\(\^\/\|\^\[A-Za-z\]:\)'[\s\S]*?ELSE NULL END AS source_file/);
    assert.ok(!scopeSelect[0].includes("C:\\"));
  } finally {
    if (old === undefined) delete process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON; else process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = old;
  }
});

test("WP6 database-backed assessment detail API response integration", async t => {
  const assessmentId = process.env.SAPPHIRE_LIVE_ASSESSMENT_ID;
  if (!assessmentId) return t.skip("Set SAPPHIRE_LIVE_ASSESSMENT_ID to exercise the optional Compose integration");
  const response = await fetch(`http://127.0.0.1:8000/assessments/${assessmentId}?limit=100`);
  assert.equal(response.status, 200);
  const detail = await response.json();
  assert.equal(detail.id, assessmentId);
  assert.equal(detail.status, "completed");
  assert.equal(detail.discovery.state, "complete");
  assert.equal(detail.discovery.endpoint_count, detail.discovery.endpoints.items.length);
  assert.equal(detail.discovery.match_count, detail.discovery.matches.items.length);
  assert.ok(detail.discovery.endpoints.items.length > 0);
  for (const endpoint of detail.discovery.endpoints.items) {
    assert.equal(typeof endpoint.id, "string");
    assert.equal(typeof endpoint.tool_run_id, "string");
    assert.equal(typeof endpoint.artifact_id, "string");
    assert.equal(endpoint.method, "GET");
    assert.ok(!endpoint.path.includes("?"));
  }
  for (const match of detail.discovery.matches.items) {
    assert.equal(typeof match.id, "string");
    assert.ok(["matched", "source_only", "runtime_only", "unresolved"].includes(match.coverage_class));
    assert.ok(Array.isArray(match.candidate_source_route_ids));
    assert.ok(match.candidate_source_route_ids.every(id => typeof id === "string"));
  }
});

test("WP7 dashboard DTO and render guards cover discovery states, pagination and safe provenance", async () => {
  const types = await readFile(resolve(root, "apps/web/lib/types.ts"), "utf8");
  const panel = await readFile(resolve(root, "apps/web/components/discovery-panel.tsx"), "utf8");
  const upload = await readFile(resolve(root, "apps/web/components/new-assessment-form.tsx"), "utf8");
  for (const state of ["not_authorized", "pending", "running", "complete", "incomplete", "failed", "cancelled", "empty"]) {
    assert.ok(types.includes(`'${state}'`), `web DTO misses state ${state}`);
    assert.ok(panel.includes(`${state}:`), `dashboard label misses state ${state}`);
  }
  for (const coverageClass of ["matched", "source_only", "runtime_only", "unresolved"]) assert.ok(panel.includes(`'${coverageClass}'`) || panel.includes(`\`${coverageClass}\``), `dashboard misses ${coverageClass}`);
  assert.match(panel, /discovery\.endpoints\.next_cursor === null/);
  assert.match(panel, /discovery\.matches\.next_cursor === null/);
  assert.match(panel, /No endpoints were persisted/);
  assert.match(panel, /discovery\.scope\.path_prefixes\.join/);
  assert.match(panel, /runtime_endpoint_id/);
  assert.match(panel, /raw_pointer/);
  assert.ok(!types.includes("pinned_ips"), "client DTO must not expose resolved pinned IPs");
  assert.match(upload, /Static intake only \(default\)/);
  assert.match(upload, /disabled=\{discoveryProfile !== 'juiceshop'\}/);
  assert.match(upload, /whole-origin HTTP scope with GET only/);
});
