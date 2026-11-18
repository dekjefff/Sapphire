import { isIP } from "node:net";

export type OperatorDiscoveryProfile = {
  origin: string;
  pinned_ips: string[];
  policy_revision: string;
  path_mode: "whole_origin" | "prefix";
  path_prefixes: string[];
};

const JUICESHOP_PROFILE: OperatorDiscoveryProfile = {
  origin: "http://juiceshop:3000", pinned_ips: ["172.31.80.10"],
  policy_revision: "juiceshop-local-v1", path_mode: "whole_origin", path_prefixes: [],
};

function isExactCanonicalOrigin(value: unknown): value is string {
  if (typeof value !== "string" || value.includes("*") || value.includes("\\")) return false;
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "http:" || parsed.protocol === "https:")
      && !parsed.username && !parsed.password && !parsed.search && !parsed.hash
      && parsed.pathname === "/" && parsed.origin === value;
  } catch { return false; }
}

function configuredProfiles(): OperatorDiscoveryProfile[] {
  const raw = process.env.DISCOVERY_SCOPE_ALLOWLIST_JSON;
  if (!raw) return [];
  try {
    const data: unknown = JSON.parse(raw);
    if (!Array.isArray(data) || data.length > 100) return [];
    return data.flatMap((entry): OperatorDiscoveryProfile[] => {
      if (!entry || typeof entry !== "object") return [];
      const item = entry as Record<string, unknown>;
      if (!isExactCanonicalOrigin(item.origin) || !Array.isArray(item.pinned_ips)
        || item.pinned_ips.length < 1 || item.pinned_ips.length > 32
        || !item.pinned_ips.every((ip) => typeof ip === "string" && isIP(ip) !== 0)
        || (item.policy_revision !== undefined && (typeof item.policy_revision !== "string" || item.policy_revision.length < 1 || item.policy_revision.length > 64))
        || (item.path_mode !== undefined && item.path_mode !== "whole_origin" && item.path_mode !== "prefix")
        || (item.path_prefixes !== undefined && (!Array.isArray(item.path_prefixes) || item.path_prefixes.length > 100 || !item.path_prefixes.every((path) => typeof path === "string" && path.length <= 2048)))
        || (item.path_mode === "prefix" && (new URL(item.origin).protocol !== "http:" || !Array.isArray(item.path_prefixes) || item.path_prefixes.length === 0))) return [];
      return [{ origin: item.origin, pinned_ips: [...new Set(item.pinned_ips as string[])],
        policy_revision: String(item.policy_revision ?? "operator-v1"),
        path_mode: (item.path_mode ?? "whole_origin") as "whole_origin" | "prefix",
        path_prefixes: (item.path_prefixes ?? []) as string[] }];
    });
  } catch { return []; }
}

export function getDiscoveryProfiles(): OperatorDiscoveryProfile[] {
  return [JUICESHOP_PROFILE, ...configuredProfiles()];
}

export function findDiscoveryProfile(origin: string): OperatorDiscoveryProfile | null {
  if (!isExactCanonicalOrigin(origin)) return null;
  return getDiscoveryProfiles().find((profile) => profile.origin === origin) ?? null;
}

export function isConfiguredDiscoveryOrigin(origin: string): boolean {
  return findDiscoveryProfile(origin) !== null;
}

export function isBuiltInLocalTargetHost(hostname: string): boolean {
  return new Set(["localhost", "127.0.0.1", "[::1]", "juiceshop"]).has(hostname.toLowerCase());
}
