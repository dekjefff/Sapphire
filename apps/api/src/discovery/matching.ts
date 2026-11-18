/** Deterministic comparison of observed GET paths and statically identified routes. */
export type SourceRouteForMatch = {
  id: string;
  method: string;
  path: string;
  source_file: string | null;
  source_line: number | null;
};

export type RuntimePathForMatch = { id: string; method: string; path: string };
export type RouteMatchPlan = {
  coverage_class: "matched" | "source_only" | "runtime_only" | "unresolved";
  runtime_endpoint_id: string | null;
  source_route_id: string | null;
  source_method: "GET" | null;
  source_route: string | null;
  source_file: string | null;
  source_line: number | null;
  candidate_source_route_ids: string[];
  reason_code: "route_matched" | "source_only_not_observed" | "no_source_route_match" | "unresolved_route";
};

/** Canonical comparison paths ignore query/fragment, duplicate slashes and trailing slashes. */
export function normalizeRoutePath(value: string): string {
  const withoutSuffix = value.split(/[?#]/, 1)[0] || "/";
  const leading = withoutSuffix.startsWith("/") ? withoutSuffix : `/${withoutSuffix}`;
  return leading.replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/";
}

function routeMatches(pattern: string, endpoint: string): boolean {
  const source = normalizeRoutePath(pattern).split("/").slice(1);
  const target = normalizeRoutePath(endpoint).split("/").slice(1);
  let i = 0;
  for (; i < source.length; i += 1) {
    const segment = source[i]!;
    const catchAll = /^\[\.\.\.[^\]]+\]$/.test(segment) || /^:[A-Za-z_$][\w$]*\*$/.test(segment);
    const parameter = /^\[[^\]]+\]$/.test(segment) || /^:[A-Za-z_$][\w$]*$/.test(segment);
    if (catchAll) return true;
    if (i >= target.length || (!parameter && segment !== target[i])) return false;
  }
  return i === target.length;
}

/**
 * Produces idempotent logical rows. Multiple route candidates are retained as unresolved;
 * no source route is selected based on order or confidence.
 */
export function planRouteMatches(sourceRoutes: SourceRouteForMatch[], endpoints: RuntimePathForMatch[]): RouteMatchPlan[] {
  const sources = sourceRoutes.filter((route) => route.method.toUpperCase() === "GET");
  const seenSources = new Set<string>();
  const matchedSourceIds = new Set<string>();
  const rows: RouteMatchPlan[] = [];

  for (const endpoint of endpoints) {
    if (endpoint.method.toUpperCase() !== "GET") continue;
    const canonical = normalizeRoutePath(endpoint.path);
    const candidates = sources.filter((route) => routeMatches(route.path, canonical));
    if (candidates.length > 1) {
      for (const candidate of candidates) matchedSourceIds.add(candidate.id);
      rows.push({ coverage_class: "unresolved", runtime_endpoint_id: endpoint.id, source_route_id: null,
        source_method: null, source_route: null, source_file: null, source_line: null,
        candidate_source_route_ids: candidates.map((route) => route.id).sort(), reason_code: "unresolved_route" });
      continue;
    }
    if (candidates.length === 1) {
      const route = candidates[0]!;
      matchedSourceIds.add(route.id);
      rows.push({ coverage_class: "matched", runtime_endpoint_id: endpoint.id, source_route_id: route.id,
        source_method: "GET", source_route: normalizeRoutePath(route.path), source_file: route.source_file,
        source_line: route.source_line, candidate_source_route_ids: [route.id], reason_code: "route_matched" });
    } else {
      rows.push({ coverage_class: "runtime_only", runtime_endpoint_id: endpoint.id, source_route_id: null,
        source_method: null, source_route: null, source_file: null, source_line: null,
        candidate_source_route_ids: [], reason_code: "no_source_route_match" });
    }
  }

  for (const route of sources) {
    if (matchedSourceIds.has(route.id) || seenSources.has(route.id)) continue;
    seenSources.add(route.id);
    rows.push({ coverage_class: "source_only", runtime_endpoint_id: null, source_route_id: route.id,
      source_method: "GET", source_route: normalizeRoutePath(route.path), source_file: route.source_file,
      source_line: route.source_line, candidate_source_route_ids: [], reason_code: "source_only_not_observed" });
  }
  return rows;
}
import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";


function relativeSourceFile(value: unknown): string | null {
  if (typeof value !== "string" || !value || value.length > 2048) return null;
  const normalized = value.replace(/\\/g, "/");
  if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized) || normalized.split("/").some((part) => part === "..")) return null;
  return normalized;
}

/**
 * Replaces an assessment's route comparisons with a deterministic current snapshot.
 * Call inside the caller's transaction after routes, endpoints, and artifact metadata
 * have been persisted; transaction ownership stays with the coordinator.
 */
export async function refreshRouteMatches(clientOrPool: Pool | PoolClient, assessmentId: string): Promise<void> {
  const [sourceResult, endpointResult] = await Promise.all([
    clientOrPool.query("SELECT id,method,path,source_file,source_line FROM discovered_routes WHERE assessment_id=$1 ORDER BY id", [assessmentId]),
    clientOrPool.query("SELECT e.id,e.tool_run_id,e.artifact_id,e.observed_method AS method,e.path,e.scope_policy_sha256,a.metadata->'raw_pointers' AS raw_pointers FROM runtime_endpoints e JOIN scan_artifacts a ON a.id=e.artifact_id AND a.assessment_id=e.assessment_id AND a.tool_run_id=e.tool_run_id WHERE e.assessment_id=$1 ORDER BY e.id", [assessmentId]),
  ]);
  const sourceRoutes: SourceRouteForMatch[] = sourceResult.rows.map((route) => ({
    id: String(route.id), method: String(route.method), path: String(route.path),
    source_file: relativeSourceFile(route.source_file), source_line: route.source_line === null ? null : Number(route.source_line),
  }));
  const endpoints = endpointResult.rows.map((endpoint) => ({ id: String(endpoint.id), method: String(endpoint.method), path: String(endpoint.path) }));
  const rows = planRouteMatches(sourceRoutes, endpoints);
  const sourceById = new Map(sourceRoutes.map((route) => [route.id, route]));
  const endpointById = new Map(endpointResult.rows.map((endpoint) => [String(endpoint.id), endpoint]));

  await clientOrPool.query("DELETE FROM endpoint_route_matches WHERE assessment_id=$1", [assessmentId]);
  for (const match of rows) {
    const source = match.source_route_id ? sourceById.get(match.source_route_id) : null;
    const endpoint = match.runtime_endpoint_id ? endpointById.get(match.runtime_endpoint_id) : null;
    const pointers = endpoint?.raw_pointers && typeof endpoint.raw_pointers === "object" ? endpoint.raw_pointers as Record<string, unknown> : {};
    const pointer = endpoint && typeof pointers[String(endpoint.id)] === "string" ? pointers[String(endpoint.id)] : null;
    const evidence = {
      ...(source ? { source_route_id: source.id } : {}),
      ...(endpoint ? { tool_run_id: String(endpoint.tool_run_id), artifact_id: String(endpoint.artifact_id), raw_pointer: pointer, scope_policy_sha256: String(endpoint.scope_policy_sha256) } : {}),
    };
    await clientOrPool.query(
      "INSERT INTO endpoint_route_matches (id,assessment_id,runtime_endpoint_id,coverage_class,source_method,source_route,source_file,source_line,candidate_source_route_ids,reason_code,evidence) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
      [randomUUID(), assessmentId, match.runtime_endpoint_id, match.coverage_class, match.source_method,
        match.source_route, source?.source_file ?? null, source?.source_line ?? null,
        JSON.stringify(match.candidate_source_route_ids), match.reason_code, JSON.stringify(evidence)],
    );
  }
}
