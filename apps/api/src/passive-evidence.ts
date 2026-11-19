import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { isUuid } from "./types.js";

type SessionState = "authenticated" | "anonymous";
type Session = { state: SessionState; method: "server_session" | "application_session"; role?: "user" | "admin" | "service" };
type Outcome = "observed" | "failed" | "skipped";
type Reason = "not_reached" | "error" | "not_applicable";
type PlanItem = { id: string; label?: string } & ({ kind: "page" } | { kind: "flow_step"; flow_id: string });
type Item = PlanItem & { status: "pending" | Outcome; first_request?: number; last_request?: number; reason?: Reason };
type Exchange = { startedDateTime: string; request: { method: string }; response: { status: number } };
type BoundExchange = Exchange & { _sapphire_route_tag: string };
type SafeHar<T extends Exchange = Exchange> = { log: { version: "1.2"; entries: T[] } };
type Counts = { expected: number; observed: number; failed: number; skipped: number; pending: number; processed: number; remaining: number; uncovered: number; requests: number };
type CaptureError = "collection_failed" | "session_check_failed";
type Event = { run_id: string; at: string; status: "queued" | "running" | "completed" | "failed"; counts: Counts; error?: CaptureError };
type Manifest = {
  version: 1; run_id: string; scope_id: string; status: Event["status"]; created_at: string;
  started_at?: string; finished_at?: string;
  session?: Session & { checked_at: string; first_request: number | null; last_request: number | null };
  expected: Item[]; request_count: number; events: Event[]; error?: CaptureError; har_sha256?: string;
};
function sanitizeExchange(input: unknown): Exchange {
  if (!input || typeof input !== "object") throw new Error("Invalid HAR");
  const entry = input as { startedDateTime?: unknown; request?: { method?: unknown }; response?: { status?: unknown } };
  const verb = entry.request?.method, status = entry.response?.status, time = entry.startedDateTime;
  if (typeof verb !== "string" || !/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(verb) ||
      typeof status !== "number" || !Number.isInteger(status) || status < 0 || status > 599 ||
      typeof time !== "string" || time.length > 40 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(time) || !Number.isFinite(Date.parse(time))) throw new Error("Invalid HAR");
  return { startedDateTime: new Date(time).toISOString(), request: { method: verb }, response: { status } };
}
function harEntries(input: unknown): unknown[] {
  if (!input || typeof input !== "object") throw new Error("Invalid HAR");
  const root = input as { log?: { entries?: unknown } };
  if (!Array.isArray(root.log?.entries) || root.log.entries.length > 10000) throw new Error("Invalid HAR");
  return root.log.entries;
}
/** Allowlist exchange metadata. URLs, bodies, headers and cookies are never retained. */
export function sanitizeHar(input: unknown): SafeHar {
  return { log: { version: "1.2", entries: harEntries(input).map(sanitizeExchange) } };
}
function routeDigest(value: unknown): string {
  const url = typeof value === "string" && value.length <= 8192 ? URL.parse(value) : null;
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) throw new Error("Invalid HAR URL");
  return createHash("sha256").update(url.origin).update(url.pathname).digest("hex");
}
function routeTag(pathDigest: string, key: Buffer, runId: string): string {
  return createHmac("sha256", key).update("sapphire-har-route-v1\0").update(runId).update(pathDigest).digest("hex");
}
function bindHar(input: unknown, key: Buffer, runId: string, allowRedacted: boolean): SafeHar<BoundExchange> {
  const entries = harEntries(input).map((value) => {
    const exchange = sanitizeExchange(value);
    const entry = value as { request: { url?: unknown }; _sapphire_route_tag?: unknown };
    const tag = entry._sapphire_route_tag;
    if (allowRedacted && entry.request.url === undefined && typeof tag === "string" && /^[a-f0-9]{64}$/.test(tag)) {
      return { ...exchange, _sapphire_route_tag: tag };
    }
    return { ...exchange, _sapphire_route_tag: routeTag(routeDigest(entry.request.url), key, runId) };
  });
  return { log: { version: "1.2", entries } };
}
const digest = (har: SafeHar) => createHash("sha256").update(JSON.stringify(har)).digest("hex");
const sign = (manifest: Manifest, key: Buffer) => createHmac("sha256", key).update(JSON.stringify(manifest)).digest("hex");
function validKey(key: Buffer): void { if (!Buffer.isBuffer(key) || key.length < 32) throw new Error("Invalid signing key"); }
function counts(manifest: Manifest): Counts {
  const expected = manifest.expected.length;
  const observed = manifest.expected.filter(item => item.status === "observed").length;
  const failed = manifest.expected.filter(item => item.status === "failed").length;
  const skipped = manifest.expected.filter(item => item.status === "skipped").length;
  const pending = expected - observed - failed - skipped;
  return {
    expected, observed, failed, skipped, pending, processed: expected - pending,
    remaining: pending, uncovered: expected - observed, requests: manifest.request_count,
  };
}
const validLabel = (label: unknown): label is string =>
  typeof label === "string" && label.length <= 100 && /^[\p{L}\p{M}\p{N} /:_{}-]+$/u.test(label) && label.trim() === label;
const uuid = z.string().refine(isUuid);
const timestamp = z.iso.datetime({ precision: 3 });
const itemCount = z.number().int().min(0).max(1000);
const requestCount = z.number().int().min(0).max(10000);
const requestIndex = requestCount.min(1);
const captureError = z.enum(["collection_failed", "session_check_failed"]);
const outcomeFields = {
  id: uuid,
  label: z.string().refine(validLabel).optional(),
  status: z.enum(["pending", "observed", "failed", "skipped"]),
  first_request: requestIndex.optional(),
  last_request: requestIndex.optional(),
  reason: z.enum(["not_reached", "error", "not_applicable"]).optional(),
};
const manifestShape = z.strictObject({
  version: z.literal(1),
  run_id: uuid,
  scope_id: uuid,
  status: z.enum(["completed", "failed"]),
  created_at: timestamp,
  started_at: timestamp.optional(),
  finished_at: timestamp,
  session: z.strictObject({
    state: z.enum(["authenticated", "anonymous"]),
    method: z.enum(["server_session", "application_session"]),
    role: z.enum(["user", "admin", "service"]).optional(),
    checked_at: timestamp,
    first_request: requestIndex.nullable(),
    last_request: requestIndex.nullable(),
  }).optional(),
  expected: z.array(z.discriminatedUnion("kind", [
    z.strictObject({ ...outcomeFields, kind: z.literal("page") }),
    z.strictObject({ ...outcomeFields, kind: z.literal("flow_step"), flow_id: uuid }),
  ])).max(1000),
  request_count: requestCount,
  events: z.array(z.strictObject({
    run_id: uuid,
    at: timestamp,
    status: z.enum(["queued", "running", "completed", "failed"]),
    counts: z.strictObject({
      expected: itemCount, observed: itemCount, failed: itemCount, skipped: itemCount,
      pending: itemCount, processed: itemCount, remaining: itemCount, uncovered: itemCount, requests: requestCount,
    }),
    error: captureError.optional(),
  })).min(2).max(11003),
  error: captureError.optional(),
  har_sha256: z.string().regex(/^[a-f0-9]{64}$/),
});
/** Use only in the instrumented application. checkSession must read trusted first-party session state. */
export class PassiveEvidenceCapture {
  private m: Manifest;
  private exchanges: { exchange: Exchange; pathDigest: string }[] = [];
  private starting = false;
  constructor(scopeId: string, expected: PlanItem[]) {
    if (!isUuid(scopeId) || !Array.isArray(expected) || expected.length > 1000 ||
        expected.some(item => !item || !isUuid(item.id) || (item.kind !== "page" && item.kind !== "flow_step") ||
          (item.kind === "flow_step" && !isUuid(item.flow_id)) || (item.label !== undefined && !validLabel(item.label))) ||
        new Set(expected.map(item => item.id)).size !== expected.length) throw new Error("Invalid capture plan");
    const created_at = new Date().toISOString();
    this.m = { version: 1, run_id: randomUUID(), scope_id: scopeId, status: "queued", created_at,
      expected: expected.map((item): Item => ({
        id: item.id, ...(item.label ? { label: item.label } : {}), status: "pending",
        ...(item.kind === "page" ? { kind: "page" } : { kind: "flow_step", flow_id: item.flow_id }),
      })), request_count: 0, events: [] };
    this.event();
  }
  private event(error?: CaptureError): void {
    this.m.events.push({
      run_id: this.m.run_id, at: new Date().toISOString(), status: this.m.status, counts: counts(this.m),
      ...(error ? { error } : {}),
    });
  }
  async start(checkSession: () => Session | Promise<Session>): Promise<void> {
    if (this.m.status !== "queued" || this.starting) throw new Error("Invalid capture state");
    this.starting = true;
    try {
      const result = await checkSession();
      if (!result || !["authenticated", "anonymous"].includes(result.state) ||
          !["server_session", "application_session"].includes(result.method) ||
          (result.role !== undefined && (result.state !== "authenticated" || !["user", "admin", "service"].includes(result.role)))) {
        throw new Error("Invalid session check");
      }
      const checked_at = new Date().toISOString();
      this.m.status = "running";
      this.m.started_at = checked_at;
      this.m.session = {
        state: result.state, method: result.method, ...(result.role ? { role: result.role } : {}),
        checked_at, first_request: null, last_request: null,
      };
      this.event();
    } catch {
      this.m.status = "failed";
      this.m.finished_at = new Date().toISOString();
      this.m.error = "session_check_failed";
      this.event("session_check_failed");
      throw new Error("Passive capture session check failed");
    } finally {
      this.starting = false;
    }
  }
  /** Record an exchange already observed by the first-party application, in HAR order. */
  observeRequest(exchange: unknown): void {
    const session = this.m.session;
    if (this.m.status !== "running" || !session || this.exchanges.length >= 10000) throw new Error("Invalid capture state");
    const sanitized = sanitizeExchange(exchange);
    const started = Date.parse(sanitized.startedDateTime);
    if (started < Date.parse(session.checked_at) || started > Date.now()) {
      throw new Error("Exchange is outside the capture session window");
    }
    const { request } = exchange as { request: { url?: unknown } };
    this.exchanges.push({ exchange: sanitized, pathDigest: routeDigest(request.url) });
    this.m.request_count = this.exchanges.length;
    session.first_request = 1;
    session.last_request = this.exchanges.length;
    this.event();
  }
  recordItem(id: string, status: Outcome, range?: { first: number; last: number }, reason?: Reason): void {
    if (this.m.status !== "running") throw new Error("Invalid capture state");
    const item = this.m.expected.find(entry => entry.id === id);
    if (!item || item.status !== "pending" || !["observed", "failed", "skipped"].includes(status)) throw new Error("Invalid item");
    if (status === "observed") {
      if (!range || !Number.isInteger(range.first) || !Number.isInteger(range.last) || range.first < 1 || range.last < range.first || range.last > this.m.request_count || reason !== undefined) throw new Error("Invalid request range");
      Object.assign(item, { status, first_request: range.first, last_request: range.last });
    } else {
      if (range || !reason || !["not_reached", "error", "not_applicable"].includes(reason)) throw new Error("Invalid item reason");
      Object.assign(item, { status, reason });
    }
    this.event();
  }
  progress() { return { manifest: structuredClone(this.m), counts: counts(this.m) }; }
  finish(input: unknown, key: Buffer, failed = false) {
    const failedAtStart = this.m.error === "session_check_failed" && !this.m.har_sha256;
    if (this.m.status !== "running" && !failedAtStart) throw new Error("Invalid capture state");
    validKey(key);
    const har = bindHar(input, key, this.m.run_id, false);
    const observed = this.exchanges.map(({ exchange, pathDigest }) => ({
      ...exchange, _sapphire_route_tag: routeTag(pathDigest, key, this.m.run_id),
    }));
    if (JSON.stringify(har.log.entries) !== JSON.stringify(observed)) throw new Error("Observed exchanges do not match HAR");
    if (!failedAtStart) {
      this.m.status = failed ? "failed" : "completed";
      this.m.finished_at = new Date().toISOString();
      if (failed) this.m.error = "collection_failed";
      this.event(this.m.error);
    }
    this.m.har_sha256 = digest(har);
    const manifest = structuredClone(this.m);
    return { manifest, signature: sign(manifest, key), har };
  }
}
/** Persist only this return value. Uploaded assertions do not become verified. */
export function importPassiveEvidence(input: { har: unknown; manifest?: unknown; signature?: unknown; assertion?: unknown }, key?: Buffer) {
  const har = sanitizeHar(input.har);
  let manifest: Manifest | undefined;
  if (key && input.manifest && typeof input.manifest === "object" &&
      typeof input.signature === "string" && /^[a-f0-9]{64}$/.test(input.signature)) {
    validKey(key);
    const expected = Buffer.from(sign(input.manifest as Manifest, key), "hex");
    if (timingSafeEqual(expected, Buffer.from(input.signature, "hex"))) {
      const parsed = manifestShape.safeParse(input.manifest);
      if (parsed.success && parsed.data.request_count === har.log.entries.length &&
          parsed.data.events.every(event => event.run_id === parsed.data.run_id)) {
        const boundHar = bindHar(input.har, key, parsed.data.run_id, true);
        if (parsed.data.har_sha256 === digest(boundHar)) manifest = parsed.data;
      }
    }
  }
  if (!manifest) {
    const assertion = input.assertion === "authenticated" || input.assertion === "anonymous" ? input.assertion : undefined;
    return { har, authentication: assertion ? "asserted" as const : "unverified" as const, ...(assertion ? { asserted_session: assertion } : {}), coverage: "unknown" as const };
  }
  const summary = counts(manifest);
  const session = manifest.session;
  return { har, manifest: structuredClone(manifest), authentication: session ? "verified" as const : "unverified" as const,
    ...(session ? { session: structuredClone(session) } : {}),
    coverage: summary.processed ? "known" as const : "unknown" as const, counts: summary,
    observed: manifest.expected.filter(item => item.status === "observed"), gaps: manifest.expected.filter(item => item.status !== "observed") };
}
