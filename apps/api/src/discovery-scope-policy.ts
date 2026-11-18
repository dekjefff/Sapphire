import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { DiscoveryScope, DiscoveryScopeSchema } from "./discovery-contracts.js";

export type DiscoveryScopeApproval = {
  scope_id: string;
  assessment_id: string;
  origin: string;
  path_mode: "whole_origin" | "prefix";
  path_prefixes?: string[];
  pinned_ips: string[];
  policy_revision: string;
  authorization_actor: string;
  authorized_at: string;
  expires_at: string;
};

function reject(message: string): never { throw new Error(message); }

function safePath(path: string): string {
  if (!path.startsWith("/") || path.includes("\\") || /%(?:2f|5c)/i.test(path)) reject("Discovery scope path is invalid");
  if (/%(?![0-9a-f]{2})/i.test(path)) reject("Discovery scope path has malformed encoding");
  for (const segment of path.split("/")) {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); }
    catch { return reject("Discovery scope path has malformed encoding"); }
    if (decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\")) reject("Discovery scope path contains an ambiguous segment");
  }
  return path.replace(/%[0-9a-f]{2}/gi, (match) => match.toUpperCase());
}

function normalizePrefix(prefix: string): string {
  if (prefix.includes("?") || prefix.includes("#")) reject("Discovery scope prefixes cannot contain query or fragment data");
  return safePath(prefix).replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/";
}

function canonicalOrigin(origin: string): { scheme: "http" | "https"; host: string; port: number } {
  if (origin.includes("#") || origin.includes("?")) reject("Discovery origin cannot contain query or fragment data");
  const rawOrigin = origin.match(/^https?:\/\/([^/?#]*)(\/[^?#]*)?$/i);
  if (!rawOrigin || rawOrigin[1].includes("\\")) reject("Discovery origin is invalid");
  const rawPath = rawOrigin[2] || "/";
  // Validate before WHATWG URL normalization, which erases literal and encoded dot segments.
  safePath(rawPath);
  if (rawPath !== "/") reject("Discovery origin must not include a path");
  let parsed: URL;
  try { parsed = new URL(origin); }
  catch { return reject("Discovery origin is invalid"); }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") reject("Discovery origin scheme is unsupported");
  if (parsed.username || parsed.password) reject("Credentials are not allowed in a discovery origin");
  if (parsed.pathname !== "/") reject("Discovery origin must not include a path");
  const host = parsed.hostname.toLowerCase();
  if (!host || host.includes("*") || host.endsWith(".")) reject("Discovery origin host must be exact");
  const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  return { scheme: parsed.protocol.slice(0, -1) as "http" | "https", host, port };
}

function canonicalIps(values: string[]): string[] {
  if (values.length > 32 || values.some((value) => isIP(value) === 0)) reject("Discovery scope pinned addresses are invalid");
  return [...new Set(values)].sort();
}

function hashPolicy(scope: Omit<DiscoveryScope, "policy_sha256">): string {
  const policy = {
    assessment_id: scope.assessment_id, scheme: scope.scheme, host: scope.host, port: scope.port,
    path_mode: scope.path_mode, path_prefixes: scope.path_prefixes, allowed_methods: scope.allowed_methods,
    pinned_ips: scope.pinned_ips, policy_revision: scope.policy_revision,
    authorization_actor: scope.authorization_actor, authorized_at: scope.authorized_at, expires_at: scope.expires_at,
  };
  return createHash("sha256").update(JSON.stringify(policy)).digest("hex");
}

export function createDiscoveryScope(input: DiscoveryScopeApproval): DiscoveryScope {
  const origin = canonicalOrigin(input.origin);
  const prefixes = input.path_mode === "prefix" ? [...new Set((input.path_prefixes ?? []).map(normalizePrefix))].sort() : [];
  if (input.path_mode === "prefix" && origin.scheme !== "http") reject("Path-limited HTTPS discovery is unsupported; approve the whole HTTPS origin");
  if (input.path_mode === "prefix" && prefixes.length === 0) reject("At least one HTTP path prefix is required");
  if (input.path_mode === "whole_origin" && (input.path_prefixes?.length ?? 0) > 0) reject("Whole-origin discovery cannot include path prefixes");
  const unsigned = {
    scope_id: input.scope_id, assessment_id: input.assessment_id, ...origin, path_mode: input.path_mode,
    path_prefixes: prefixes, allowed_methods: ["GET"] as ["GET"], pinned_ips: canonicalIps(input.pinned_ips),
    policy_revision: input.policy_revision, authorization_actor: input.authorization_actor,
    authorized_at: new Date(input.authorized_at).toISOString(), expires_at: new Date(input.expires_at).toISOString(),
  };
  return DiscoveryScopeSchema.parse({ ...unsigned, policy_sha256: hashPolicy(unsigned) });
}

export function verifyDiscoveryScope(scope: DiscoveryScope): boolean {
  const parsed = DiscoveryScopeSchema.safeParse(scope);
  if (!parsed.success) return false;
  const { policy_sha256, ...unsigned } = parsed.data;
  return hashPolicy(unsigned) === policy_sha256;
}

function rawPathFromUrl(value: string): string {
  return value.match(/^https?:\/\/[^/?#]*(\/[^?#]*)?/i)?.[1] || "/";
}

export function assertUrlInDiscoveryScope(value: string, scope: DiscoveryScope, now = new Date()): URL {
  if (!verifyDiscoveryScope(scope)) reject("Discovery scope policy hash is invalid");
  if (now.getTime() >= Date.parse(scope.expires_at)) reject("Discovery scope has expired");
  let url: URL;
  try { url = new URL(value); }
  catch { return reject("Discovery URL is invalid"); }
  if (url.username || url.password || url.hash) reject("Credentials and fragments are not allowed in discovery URLs");
  if (url.protocol.slice(0, -1) !== scope.scheme || url.hostname.toLowerCase() !== scope.host
    || Number(url.port || (url.protocol === "https:" ? 443 : 80)) !== scope.port) reject("Discovery URL is outside the approved origin");
  const path = safePath(rawPathFromUrl(value));
  if (scope.path_mode === "prefix" && !scope.path_prefixes.some((prefix) => prefix === "/" || path === prefix || path.startsWith(`${prefix}/`))) {
    reject("Discovery URL is outside the approved path prefixes");
  }
  return url;
}

export function canonicalPolicyJson(scope: DiscoveryScope): string {
  if (!verifyDiscoveryScope(scope)) reject("Discovery scope policy hash is invalid");
  const { policy_sha256: _hash, ...unsigned } = scope;
  return JSON.stringify(unsigned);
}
