import { assertUrlInDiscoveryScope } from "../discovery-scope-policy.js";
import type { DiscoveryScope } from "../discovery-contracts.js";

export type SanitizedObservation = {
  url: string;
  path: string;
  referrer_path: string | null;
  status_code: number | null;
  content_type: string | null;
  content_length: number | null;
  title: string | null;
  redirect_observed: boolean;
};

export class DiscoveryParseError extends Error {
  constructor() { super("Discovery tool output is malformed or exceeds safe parser limits"); }
}

const MAX_LINE_BYTES = 64 * 1024;
const MAX_URL_BYTES = 2048;

function boundedString(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return clean ? clean.slice(0, max) : null;
}

function positiveInt(value: unknown): number | null {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string" && /^\d{1,16}$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

function nested(value: unknown, ...keys: string[]): unknown {
  let current = value;
  for (const key of keys) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function safeCanonicalUrl(raw: unknown, scope: DiscoveryScope): { url: string; path: string } | null {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_URL_BYTES) return null;
  let parsed: URL;
  try { parsed = new URL(raw); } catch { return null; }
  if (parsed.username || parsed.password || parsed.hash) return null;
  // Query strings can contain secrets. Validate scope using the URL, then persist only origin + path.
  try { assertUrlInDiscoveryScope(raw, scope); } catch { return null; }
  parsed.search = "";
  parsed.hash = "";
  const path = parsed.pathname || "/";
  return { url: `${parsed.origin}${path}`, path };
}

function safeReferrer(raw: unknown, scope: DiscoveryScope): string | null {
  if (typeof raw !== "string") return null;
  const canonical = safeCanonicalUrl(raw, scope);
  return canonical?.path ?? null;
}

function parseLines(input: string, scope: DiscoveryScope, kind: "httpx" | "katana"): SanitizedObservation[] {
  if (Buffer.byteLength(input, "utf8") > 8 * 1024 * 1024) throw new DiscoveryParseError();
  const observations: SanitizedObservation[] = [];
  for (const line of input.split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) throw new DiscoveryParseError();
    let item: unknown;
    try { item = JSON.parse(line); } catch { throw new DiscoveryParseError(); }
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new DiscoveryParseError();
    const url = kind === "httpx"
      ? (item as Record<string, unknown>).url
      : ((item as Record<string, unknown>).url ?? (item as Record<string, unknown>)["matched-at"] ?? nested(item, "request", "endpoint"));
    const canonical = safeCanonicalUrl(url, scope);
    // Out-of-scope or unsafe URLs are discarded. The gateway is the request-time security boundary.
    if (!canonical) continue;
    const statusRaw = kind === "httpx"
      ? (item as Record<string, unknown>).status_code
      : ((item as Record<string, unknown>).status_code ?? nested(item, "response", "status_code"));
    const status = positiveInt(statusRaw);
    const statusCode = status !== null && status >= 100 && status <= 599 ? status : null;
    const contentType = boundedString(kind === "httpx"
      ? (item as Record<string, unknown>).content_type
      : ((item as Record<string, unknown>)["content-type"] ?? nested(item, "response", "header", "Content-Type")), 256);
    const length = positiveInt(kind === "httpx"
      ? (item as Record<string, unknown>).content_length
      : ((item as Record<string, unknown>)["content-length"] ?? nested(item, "response", "content_length")));
    const title = boundedString((item as Record<string, unknown>).title ?? nested(item, "response", "title"), 512);
    const referrer = kind === "katana"
      ? ((item as Record<string, unknown>).source ?? (item as Record<string, unknown>).source_url ?? nested(item, "request", "source"))
      : undefined;
    const statusNumber = positiveInt(statusRaw);
    const redirect = Boolean((item as Record<string, unknown>).location ?? (item as Record<string, unknown>).redirect)
      || (statusNumber !== null && statusNumber >= 300 && statusNumber < 400);
    observations.push({
      url: canonical.url, path: canonical.path, referrer_path: safeReferrer(referrer, scope),
      status_code: statusCode, content_type: contentType, content_length: length, title,
      redirect_observed: redirect,
    });
  }
  return observations;
}

export function parseHttpxJsonl(input: string, scope: DiscoveryScope): SanitizedObservation[] {
  return parseLines(input, scope, "httpx");
}

export function parseKatanaJsonl(input: string, scope: DiscoveryScope): SanitizedObservation[] {
  return parseLines(input, scope, "katana");
}
