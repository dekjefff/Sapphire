import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { planRouteMatches, normalizeRoutePath } from "../dist/discovery/matching.js";
import { assessmentDetailQuerySchema, createAssessmentSchema, createZipAssessmentSchema, validateTarget } from "../dist/validation.js";
import { findDiscoveryProfile } from "../dist/discovery/authorization-profiles.js";
import { getDiscoveryBudgetDto, resolveDiscoveryState } from "../dist/discovery/assessment-summary.js";

test("route matching normalizes duplicate and trailing slashes and matches path parameters", () => {
  const result = planRouteMatches([
    { id: "101", method: "GET", path: "/users/:userId/", source_file: "src/routes.ts", source_line: 7 },
    { id: "102", method: "GET", path: "/files/[...path]", source_file: "src/files.ts", source_line: 11 },
    { id: "103", method: "GET", path: "/health", source_file: "src/health.ts", source_line: 4 },
  ], [
    { id: "ep-1", method: "GET", path: "//users/42/?ignored=1#fragment" },
    { id: "ep-2", method: "GET", path: "/files/a/b" },
    { id: "ep-3", method: "GET", path: "/orphan" },
  ]);
  assert.deepEqual(result.map((item) => item.coverage_class), ["matched", "matched", "runtime_only", "source_only"]);
  assert.equal(result[0].source_route_id, "101");
  assert.equal(result[2].reason_code, "no_source_route_match");
  assert.equal(normalizeRoutePath("//health///?q=x"), "/health");
});

test("multiple candidate routes stay unresolved with every source id", () => {
  const result = planRouteMatches([
    { id: "11", method: "GET", path: "/items/:id", source_file: "a.ts", source_line: 1 },
    { id: "12", method: "GET", path: "/items/[slug]", source_file: "b.ts", source_line: 2 },
  ], [{ id: "ep-1", method: "GET", path: "/items/x" }]);
  assert.equal(result.length, 1);
  assert.equal(result[0].coverage_class, "unresolved");
  assert.deepEqual(result[0].candidate_source_route_ids, ["11", "12"]);
});

test("intake requires an explicit true attestation and detail pagination is bounded", () => {
  const local = { project_name: "demo", repository_path: "C:/src", target_url: "http://juiceshop:3000" };
  assert.equal(createAssessmentSchema.safeParse(local).success, true);
  assert.equal(createAssessmentSchema.safeParse({ ...local, runtime_discovery_authorized: false }).success, true);
  assert.equal(createAssessmentSchema.safeParse({ ...local, runtime_discovery_authorized: true }).success, true);
  assert.equal(createZipAssessmentSchema.safeParse({ project_name: "demo", target_url: "http://juiceshop:3000", pinned_ips: ["1.1.1.1"] }).success, false);
  assert.equal(createZipAssessmentSchema.safeParse({ project_name: "demo", target_url: "http://juiceshop:3000", runtime_discovery_authorized: "true" }).success, true);
  assert.equal(createZipAssessmentSchema.safeParse({ project_name: "demo", target_url: "http://juiceshop:3000", runtime_discovery_authorized: "yes" }).success, false);
  assert.equal(assessmentDetailQuerySchema.safeParse({ limit: "100", endpoint_cursor: "0", match_cursor: "200" }).success, true);
  assert.equal(assessmentDetailQuerySchema.safeParse({ limit: "101" }).success, false);
  assert.equal(assessmentDetailQuerySchema.safeParse({ limit: "10", cursor: "NaN" }).success, false);
  assert.throws(() => validateTarget("http://juiceshop:3000/?token=secret"));
  assert.throws(() => validateTarget("http://juiceshop:3000/#fragment"));
});

test("operator exact-origin profiles are shared with intake target validation", () => {
  const original = process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON;
  try {
    process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = JSON.stringify([{ origin: "http://app.internal:8081", pinned_ips: ["192.0.2.10"], path_mode: "prefix", path_prefixes: ["/api"] }]);
    assert.equal(findDiscoveryProfile("http://app.internal:8081")?.pinned_ips[0], "192.0.2.10");
    assert.equal(validateTarget("http://app.internal:8081/api/v1"), "http://app.internal:8081/api/v1");
    assert.throws(() => validateTarget("http://other.internal:8081"));
    assert.throws(() => validateTarget("http://app.internal:8081.evil"));
    assert.equal(findDiscoveryProfile("http://juiceshop:3000")?.pinned_ips[0], "172.31.80.10");

    process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = "{malformed";
    assert.throws(() => validateTarget("http://app.internal:8081"));
    assert.equal(validateTarget("http://juiceshop:3000"), "http://juiceshop:3000/");
  } finally {
    if (original === undefined) delete process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON;
    else process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON = original;
  }
});

test("empty endpoints remain incomplete when a discovery run is incomplete", () => {
  assert.equal(resolveDiscoveryState([{ status: "completed", coverage_status: "incomplete" }], 0, 1), "incomplete");
  assert.equal(resolveDiscoveryState([{ status: "completed", coverage_status: "complete" }], 0, 1), "empty");
});

test("assessment budget DTO exposes the server-side configured profile", () => {
  const budget = getDiscoveryBudgetDto();
  assert.deepEqual(Object.keys(budget).sort(), [
    "connect_timeout_seconds", "crawl_depth", "global_concurrency", "max_response_bytes",
    "per_host_concurrency", "per_host_requests_per_second", "profile_id", "request_timeout_seconds",
    "requests_per_second", "retries", "total_response_bytes", "unique_urls", "wall_clock_seconds",
  ].sort());
  assert.equal(budget.profile_id, "discovery-default-v1");
  assert.equal(budget.crawl_depth, 3);
  assert.equal(budget.unique_urls, 500);
});

test("ZIP multipart limits allow the three assessment fields and one source file", async () => {
  const source = await readFile(new URL("../src/server.ts", import.meta.url), "utf8");
  assert.match(source, /limits:\s*\{\s*files:\s*1,\s*fileSize:\s*100\s*\*\s*1024\s*\*\s*1024,\s*fields:\s*3,\s*parts:\s*4\s*\}/);
});
