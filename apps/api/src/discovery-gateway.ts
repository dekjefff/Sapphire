import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect as tcpConnect, isIP } from "node:net";
import { promises as dns } from "node:dns";
import { access, appendFile, lstat, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { assertUrlInDiscoveryScope, verifyDiscoveryScope } from "./discovery-scope-policy.js";
import { DiscoveryBudgetProfileSchema, DiscoveryScopeSchema, DiscoveryTaskSchema, type DiscoveryBudgetProfile, type DiscoveryScope, type DiscoveryTask } from "./discovery-contracts.js";
import { isReasonCode } from "./reason-codes.js";

const REASONS = ["scope_invalid", "scope_expired", "scope_https_prefix_unsupported", "scope_path_denied", "scope_origin_denied", "dns_policy_rejected", "peer_ip_mismatch", "redirect_denied", "rate_budget_exhausted", "concurrency_budget_exhausted", "url_budget_exhausted", "byte_budget_exhausted", "timeout", "cancelled", "tool_failed"] as const;
export type GatewayReason = typeof REASONS[number];
export class GatewayDenied extends Error {
  constructor(readonly reason: GatewayReason) { super(reason); }
}

type Context = { task: DiscoveryTask; scope: DiscoveryScope; budget: DiscoveryBudgetProfile };
export type GatewayOptions = {
  workDir: string;
  eventsDir?: string;
  localTargets?: string[];
  resolveAll?: (host: string) => Promise<string[]>;
  now?: () => Date;
};

const hopHeaders = new Set(["connection", "proxy-connection", "proxy-authorization", "proxy-authenticate", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "authorization", "cookie", "set-cookie"]);
function cleanHeaders(headers: IncomingMessage["headers"]): Record<string, string | string[]> {
  const connectionTokens = String(headers.connection ?? "").split(",").map((s) => s.trim().toLowerCase());
  const blocked = new Set([...hopHeaders, ...connectionTokens]);
  const out: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!value || blocked.has(key.toLowerCase()) || key.toLowerCase() === "host") continue;
    if (key.toLowerCase() === "accept-encoding") { out[key] = "identity"; continue; }
    out[key] = value;
  }
  return out;
}

function safeLocalTarget(host: string, ip: string, port: number, targets: string[]): boolean {
  return targets.includes(`${host.toLowerCase()}:${ip}:${port}`);
}
export function isKatanaProxyProbe(tool: string, method: string | undefined, url: string | undefined): boolean {
  return tool === "katana" && (method ?? "").toUpperCase() === "GET" && url === "http://burpsuite/";
}
function dnsHost(host: string): string { return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host; }
function ipv4Number(ip: string): number { return ip.split(".").reduce((n, octet) => ((n << 8) | Number(octet)) >>> 0, 0); }
function inV4(ip: string, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4Number(ip) & mask) === (ipv4Number(base) & mask);
}
function ipv6Number(ip: string): bigint | null {
  let s = ip.toLowerCase().split("%", 1)[0]!;
  if (s.includes(".")) {
    const i = s.lastIndexOf(":"); const v4 = s.slice(i + 1);
    if (isIP(v4) !== 4) return null;
    const n = BigInt(ipv4Number(v4)); s = `${s.slice(0, i)}:${(n >> 16n).toString(16)}:${(n & 0xffffn).toString(16)}`;
  }
  const halves = s.split("::");
  const left = halves[0] ? halves[0]!.split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1]!.split(":") : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const words = [...left, ...Array(missing).fill("0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  return words.reduce((n, word) => (n << 16n) | BigInt(`0x${word}`), 0n);
}
function inV6(ip: string, base: string, bits: number): boolean {
  const n = ipv6Number(ip); const b = ipv6Number(base);
  if (n === null || b === null) return true;
  const shift = 128n - BigInt(bits); return (n >> shift) === (b >> shift);
}
export function isDisallowedAddress(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) {
    return [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]].some(([base, bits]) => inV4(ip, base as string, bits as number));
  }
  if (kind === 6) {
    const n = ipv6Number(ip);
    if (n === null) return true;
    // IPv4-mapped addresses inherit the IPv4 policy.
    if ((n >> 32n) === 0xffffn) return isDisallowedAddress(`${Number((n >> 24n) & 255n)}.${Number((n >> 16n) & 255n)}.${Number((n >> 8n) & 255n)}.${Number(n & 255n)}`);
    return [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32], ["2001::", 23], ["100::", 64]].some(([base, bits]) => inV6(ip, base as string, bits as number));
  }
  return true;
}

function parseBasic(header: string | undefined): { runId: string; hash: string } {
  if (!header || !/^Basic [A-Za-z0-9+/]+=*$/.test(header)) throw new GatewayDenied("scope_invalid");
  let decoded: string;
  try { decoded = Buffer.from(header.slice(6), "base64").toString("utf8"); } catch { throw new GatewayDenied("scope_invalid"); }
  const match = decoded.match(/^([0-9a-f-]{36}):([0-9a-f]{64})$/);
  if (!match) throw new GatewayDenied("scope_invalid");
  return { runId: match[1]!, hash: match[2]! };
}
async function jsonFile<T>(path: string): Promise<T> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024) throw new Error("Invalid bounded policy file");
    return JSON.parse(await readFile(path, "utf8")) as T;
  }
  catch { throw new GatewayDenied("scope_invalid"); }
}
async function contextFor(header: string | undefined, workDir: string): Promise<Context> {
  const { runId, hash } = parseBasic(header);
  const task = DiscoveryTaskSchema.parse(await jsonFile(join(workDir, "requests", `${runId}.json`)));
  if (task.tool_run_id !== runId || task.scope_policy_sha256 !== hash) throw new GatewayDenied("scope_invalid");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(task.budget_profile_id) || task.budget_profile_id.includes("..")) throw new GatewayDenied("scope_invalid");
  const scope = DiscoveryScopeSchema.parse(await jsonFile(join(workDir, "scopes", `${task.scope_id}.json`)));
  const budget = DiscoveryBudgetProfileSchema.parse(await jsonFile(join(workDir, "budgets", `${task.budget_profile_id}.json`)));
  if (scope.scope_id !== task.scope_id || scope.assessment_id !== task.assessment_id || scope.policy_sha256 !== hash || !verifyDiscoveryScope(scope)) throw new GatewayDenied("scope_invalid");
  if (scope.scheme === "https" && scope.path_mode === "prefix") throw new GatewayDenied("scope_https_prefix_unsupported");
  if (new Date().getTime() >= Date.parse(scope.expires_at)) throw new GatewayDenied("scope_expired");
  return { task, scope, budget };
}

export function createDiscoveryGateway(options: GatewayOptions): { server: Server; close: () => Promise<void> } {
  const { workDir } = options;
  const eventsDir = options.eventsDir ?? join(workDir, "gateway-events");
  const now = options.now ?? (() => new Date());
  const resolveAll = options.resolveAll ?? (async (host: string) => {
    if (isIP(host)) return [host];
    return [...new Set((await dns.lookup(host, { all: true, verbatim: true })).map((entry) => entry.address))];
  });
  const active = new Map<string, number>();
  const counters = new Map<string, { urls: Set<string>; bytes: number; lastRequest: number; started: number }>();
  const eventQueues = new Map<string, Promise<void>>();
  const cancelled = async (runId: string) => access(join(workDir, "cancel", runId)).then(() => true, () => false);
  async function waitForRateSlot(context: Context, state: { lastRequest: number; started: number }): Promise<void> {
    const observedAt = now().getTime();
    const spacing = Math.ceil(1000 / Math.min(context.budget.requests_per_second, context.budget.per_host_requests_per_second));
    const scheduledAt = Math.max(observedAt, state.lastRequest + spacing);
    if (scheduledAt - state.started > context.budget.wall_clock_seconds * 1000) throw new GatewayDenied("rate_budget_exhausted");
    // Reserve the slot before yielding so concurrent requests cannot select it too.
    state.lastRequest = scheduledAt;
    if (scheduledAt > observedAt) await delay(scheduledAt - observedAt);
    if (await cancelled(context.task.tool_run_id)) throw new GatewayDenied("cancelled");
    if (now().getTime() - state.started > context.budget.wall_clock_seconds * 1000) throw new GatewayDenied("timeout");
  }
  function recordDenial(runId: string | undefined, reason: GatewayReason): Promise<void> {
    if (!runId || !/^[0-9a-f-]{36}$/i.test(runId) || !REASONS.includes(reason) || !isReasonCode(reason)) return Promise.resolve();
    const previous = eventQueues.get(runId) ?? Promise.resolve();
    const next = previous.then(async () => {
      await mkdir(eventsDir, { recursive: true, mode: 0o700 });
      const file = join(eventsDir, `${runId}.jsonl`);
      let size = 0; let count = 0;
      try {
        const info = await lstat(file);
        if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024) return;
        size = info.size;
        count = (await readFile(file, "utf8")).split("\n").filter(Boolean).length;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") return;
      }
      if (count >= 256) return;
      const line = `${JSON.stringify({ timestamp: now().toISOString(), reason_code: reason })}\n`;
      const bytes = Buffer.byteLength(line);
      if (size + bytes > 64 * 1024) return;
      await appendFile(file, line, { encoding: "utf8", flag: "a", mode: 0o600 });
    }).catch(() => undefined);
    eventQueues.set(runId, next);
    void next.then(() => { if (eventQueues.get(runId) === next) eventQueues.delete(runId); });
    return next;
  }
  const runIdFromHeader = (header: string | undefined): string | undefined => {
    try { return parseBasic(header).runId; } catch { return undefined; }
  };
  const deny = (res: ServerResponse, reason: GatewayReason, status = 403, runId?: string) => {
    void recordDenial(runId, reason);
    res.writeHead(status, { "content-type": "text/plain", "content-length": "0", "x-discovery-policy-reason": reason, connection: "close" }); res.end();
  };
  async function authorize(rawUrl: string, context: Context): Promise<{ url: URL; ips: string[] }> {
    let url: URL;
    try { url = assertUrlInDiscoveryScope(rawUrl, context.scope, now()); }
    catch (error) {
      const msg = error instanceof Error ? error.message : "";
      const reason: GatewayReason = /expired/i.test(msg) ? "scope_expired" : /path/i.test(msg) ? "scope_path_denied" : /origin/i.test(msg) ? "scope_origin_denied" : "scope_invalid";
      throw new GatewayDenied(reason);
    }
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    if (port !== context.scope.port) throw new GatewayDenied("scope_origin_denied");
    let resolved: string[];
    try { resolved = [...new Set(await resolveAll(dnsHost(url.hostname)))].sort(); } catch { throw new GatewayDenied("dns_policy_rejected"); }
    if (!resolved.length || resolved.length > 32 || resolved.some((ip) => isIP(ip) === 0)) throw new GatewayDenied("dns_policy_rejected");
    const approved = new Set(context.scope.pinned_ips);
    if (resolved.some((ip) => !approved.has(ip) || (isDisallowedAddress(ip) && !safeLocalTarget(url.hostname, ip, port, options.localTargets ?? [])))) throw new GatewayDenied("dns_policy_rejected");
    if (resolved.some((ip) => !context.scope.pinned_ips.includes(ip))) throw new GatewayDenied("dns_policy_rejected");
    return { url, ips: resolved };
  }
  async function handleHttp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let ctx: Context | undefined;
    try {
      ctx = await contextFor(req.headers["proxy-authorization"], workDir);
      if (await cancelled(ctx.task.tool_run_id)) throw new GatewayDenied("cancelled");
      // Katana performs this fixed proxy bootstrap request before crawling. Answer it
      // locally so no out-of-scope connection is attempted and no run budget is spent.
      if (isKatanaProxyProbe(ctx.task.tool, req.method, req.url)) {
        res.writeHead(204, { "content-length": "0", connection: "close" });
        res.end();
        return;
      }
      if ((req.method ?? "").toUpperCase() !== "GET") throw new GatewayDenied("scope_origin_denied");
      if (!req.url || !/^https?:\/\//i.test(req.url)) throw new GatewayDenied("scope_invalid");
      const { url, ips } = await authorize(req.url, ctx);
      if (url.protocol !== "http:") throw new GatewayDenied("scope_origin_denied");
      const state = counters.get(ctx.task.tool_run_id) ?? { urls: new Set<string>(), bytes: 0, lastRequest: 0, started: now().getTime() };
      if (now().getTime() - state.started > ctx.budget.wall_clock_seconds * 1000) throw new GatewayDenied("timeout");
      const key = `${url.origin}${url.pathname}`;
      if (!state.urls.has(key) && state.urls.size >= ctx.budget.unique_urls) throw new GatewayDenied("url_budget_exhausted");
      await waitForRateSlot(ctx, state);
      state.urls.add(key); counters.set(ctx.task.tool_run_id, state);
      const count = active.get(ctx.task.tool_run_id) ?? 0;
      if (count >= ctx.budget.global_concurrency || count >= ctx.budget.per_host_concurrency) throw new GatewayDenied("concurrency_budget_exhausted");
      active.set(ctx.task.tool_run_id, count + 1);
      const ip = ips[0]!;
      const upstream = httpRequest({ protocol: "http:", hostname: ip, port: ctx.scope.port, method: "GET", path: `${url.pathname}${url.search}`, headers: { ...cleanHeaders(req.headers), host: url.host }, timeout: Math.min(ctx.budget.request_timeout_seconds, 10) * 1000, setHost: false }, (up) => {
        const status = up.statusCode ?? 502;
        if (status >= 300 && status < 400) {
          res.setHeader("x-discovery-policy-reason", "redirect_denied");
          void recordDenial(ctx!.task.tool_run_id, "redirect_denied");
        }
        const headers = up.headers;
        for (const [name, value] of Object.entries(headers)) {
          if (value === undefined || hopHeaders.has(name.toLowerCase()) || name.toLowerCase() === "location") continue;
          res.setHeader(name, value);
        }
        if (headers.location) {
          try { res.setHeader("x-discovery-redirect-origin", new URL(headers.location, url).origin.slice(0, 256)); } catch { res.setHeader("x-discovery-redirect-origin", "invalid"); }
        }
        res.writeHead(status);
        let bodyBytes = 0;
        let cancelRecorded = false;
        const cancelPoll = setInterval(() => { void cancelled(ctx!.task.tool_run_id).then((stop) => { if (stop) { if (!cancelRecorded) { cancelRecorded = true; void recordDenial(ctx!.task.tool_run_id, "cancelled"); } up.destroy(); res.destroy(); } }); }, 100);
        cancelPoll.unref();
        up.on("data", (chunk: Buffer) => {
          bodyBytes += chunk.length; state.bytes += chunk.length;
      if (bodyBytes > ctx!.budget.max_response_bytes || state.bytes > ctx!.budget.total_response_bytes) {
            void recordDenial(ctx!.task.tool_run_id, "byte_budget_exhausted"); up.destroy(); res.destroy(); return;
          }
          res.write(chunk);
        });
        up.on("end", () => { clearInterval(cancelPoll); res.end(); });
        up.on("close", () => clearInterval(cancelPoll));
        up.on("error", () => { if (!res.destroyed) res.destroy(); });
      });
      upstream.on("socket", (socket) => socket.once("connect", () => {
        const peer = socket.remoteAddress?.replace(/^::ffff:/, "");
        const selected = ip.replace(/^::ffff:/, "");
        if (peer !== selected) { void recordDenial(ctx!.task.tool_run_id, "peer_ip_mismatch"); upstream.destroy(new GatewayDenied("peer_ip_mismatch")); }
      }));
      upstream.on("timeout", () => { void recordDenial(ctx!.task.tool_run_id, "timeout"); upstream.destroy(new GatewayDenied("timeout")); });
      upstream.on("error", (error) => { if (!res.headersSent) deny(res, error instanceof GatewayDenied ? error.reason : "tool_failed", 502, ctx!.task.tool_run_id); });
      req.on("aborted", () => upstream.destroy());
      upstream.end();
      upstream.once("close", () => active.set(ctx!.task.tool_run_id, Math.max(0, (active.get(ctx!.task.tool_run_id) ?? 1) - 1)));
    } catch (error) {
      const reason = error instanceof GatewayDenied ? error.reason : "scope_invalid";
      const runId = ctx?.task.tool_run_id ?? runIdFromHeader(req.headers["proxy-authorization"]);
      deny(res, reason, 403, runId);
    }
  }
  const server = createServer((req, res) => { void handleHttp(req, res); });
  server.on("connect", (req, client, head) => {
    void (async () => {
      let ctx: Context | undefined; let upstream: import("node:net").Socket | undefined;
      try {
        ctx = await contextFor(req.headers["proxy-authorization"], workDir);
        if (await cancelled(ctx.task.tool_run_id)) throw new GatewayDenied("cancelled");
        if (ctx.scope.scheme !== "https" || ctx.scope.path_mode !== "whole_origin") throw new GatewayDenied("scope_https_prefix_unsupported");
        const target = new URL(`https://${req.url ?? ""}`);
        if (target.username || target.password || target.pathname !== "/" || target.search || target.hash || target.hostname.toLowerCase() !== ctx.scope.host || Number(target.port || 443) !== ctx.scope.port) throw new GatewayDenied("scope_origin_denied");
        const { ips } = await authorize(target.origin, ctx);
        const runState = counters.get(ctx.task.tool_run_id) ?? { urls: new Set<string>(), bytes: 0, lastRequest: 0, started: now().getTime() };
        if (now().getTime() - runState.started > ctx.budget.wall_clock_seconds * 1000) throw new GatewayDenied("timeout");
        const originKey = `https://${ctx.scope.host}:${ctx.scope.port}`;
        if (!runState.urls.has(originKey) && runState.urls.size >= ctx.budget.unique_urls) throw new GatewayDenied("url_budget_exhausted");
        await waitForRateSlot(ctx, runState);
        runState.urls.add(originKey);
        counters.set(ctx.task.tool_run_id, runState);
        const count = active.get(ctx.task.tool_run_id) ?? 0;
        if (count >= ctx.budget.global_concurrency || count >= ctx.budget.per_host_concurrency) throw new GatewayDenied("concurrency_budget_exhausted");
        active.set(ctx.task.tool_run_id, count + 1);
        upstream = tcpConnect(ctx.scope.port, ips[0]!);
        const selected = ips[0]!.replace(/^::ffff:/, "");
        upstream.once("connect", () => {
          const peer = upstream!.remoteAddress?.replace(/^::ffff:/, "");
          if (peer !== selected) { void recordDenial(ctx!.task.tool_run_id, "peer_ip_mismatch"); client.destroy(); upstream!.destroy(); return; }
          client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          if (head.length) upstream!.write(head);
          let tunnelBytes = 0;
          const stopTunnel = () => { void recordDenial(ctx!.task.tool_run_id, "byte_budget_exhausted"); client.destroy(); upstream?.destroy(); };
          client.on("data", (chunk: Buffer) => { tunnelBytes += chunk.length; if (tunnelBytes > ctx!.budget.total_response_bytes) stopTunnel(); });
          upstream!.on("data", (chunk: Buffer) => {
            tunnelBytes += chunk.length; runState.bytes += chunk.length;
            if (tunnelBytes > ctx!.budget.max_response_bytes || runState.bytes > ctx!.budget.total_response_bytes) stopTunnel();
          });
          client.pipe(upstream!); upstream!.pipe(client);
        });
        const wallTimer = setTimeout(() => { void recordDenial(ctx!.task.tool_run_id, "timeout"); upstream?.destroy(new GatewayDenied("timeout")); }, ctx.budget.wall_clock_seconds * 1000); wallTimer.unref();
        upstream.once("close", () => clearTimeout(wallTimer));
        const connectTimer = setTimeout(() => { void recordDenial(ctx!.task.tool_run_id, "timeout"); upstream?.destroy(new GatewayDenied("timeout")); }, ctx.budget.connect_timeout_seconds * 1000); connectTimer.unref();
        upstream.once("connect", () => clearTimeout(connectTimer));
        let cancelRecorded = false;
        const cancelPoll = setInterval(() => { void cancelled(ctx!.task.tool_run_id).then((stop) => { if (stop) { if (!cancelRecorded) { cancelRecorded = true; void recordDenial(ctx!.task.tool_run_id, "cancelled"); } client.destroy(); upstream?.destroy(); } }); }, 100);
        cancelPoll.unref();
        upstream.on("error", () => client.destroy());
        client.on("error", () => upstream?.destroy());
        client.on("close", () => { clearInterval(cancelPoll); upstream?.destroy(); active.set(ctx!.task.tool_run_id, Math.max(0, (active.get(ctx!.task.tool_run_id) ?? 1) - 1)); });
      } catch (error) {
        const reason = error instanceof GatewayDenied ? error.reason : "scope_invalid";
        const runId = ctx?.task.tool_run_id ?? runIdFromHeader(req.headers["proxy-authorization"]);
        void recordDenial(runId, reason);
        client.end(`HTTP/1.1 403 Forbidden\r\nX-Discovery-Policy-Reason: ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      }
    })();
  });
  return { server, close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())) };
}

if (process.env.DISCOVERY_GATEWAY_LISTEN === "1") {
  const localTargets = (process.env.DISCOVERY_LOCAL_TARGETS ?? "").split(",").filter(Boolean);
  const gateway = createDiscoveryGateway({
    workDir: process.env.DISCOVERY_WORK_DIR ?? "/discovery-work",
    eventsDir: process.env.DISCOVERY_GATEWAY_EVENTS_DIR ?? "/gateway-events",
    localTargets,
  });
  gateway.server.listen(8080, "0.0.0.0");
}
