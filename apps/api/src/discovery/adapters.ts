import type { DiscoveryBudgetProfile, DiscoveryScope, DiscoveryTask } from "../discovery-contracts.js";

export const HTTPX_VERSION = "1.12.0" as const;
export const KATANA_VERSION = "1.8.0" as const;
export const ADAPTER_VERSION = "1.0.0" as const;
export const DISCOVERY_GATEWAY_URL = "http://discovery-gateway:8080" as const;

export function buildPolicyProxyUrl(task: DiscoveryTask): string {
  if (!/^[0-9a-f-]{36}$/i.test(task.tool_run_id) || !/^[0-9a-f]{64}$/.test(task.scope_policy_sha256)) {
    throw new Error("Invalid fixed proxy identity values");
  }
  return `http://${task.tool_run_id}:${task.scope_policy_sha256}@discovery-gateway:8080`;
}

/** Fixed httpx argv for one exact origin probe; never append caller-provided options. */
export function buildHttpxArgv(task: DiscoveryTask, budget: DiscoveryBudgetProfile): string[] {
  if (task.tool !== "httpx") throw new Error("httpx adapter received a non-httpx task");
  const proxy = buildPolicyProxyUrl(task);
  return ["-u", task.seed_url, "-json", "-silent", "-no-color", "-disable-update-check", "-no-fallback-scheme", "-status-code", "-content-type", "-content-length", "-title", "-location", "-method", "GET",
    "-timeout", String(Math.ceil(budget.request_timeout_seconds)), "-retries", "0", "-rate-limit", String(Math.floor(budget.requests_per_second)),
    "-threads", "1", "-response-size-to-read", String(budget.max_response_bytes), "-response-size-to-save", String(budget.max_response_bytes),
    "-proxy", proxy];
}

/** Fixed passive Katana argv; GET-only, non-headless and with redirects disabled. */
export function buildKatanaArgv(task: DiscoveryTask, scope: DiscoveryScope, budget: DiscoveryBudgetProfile): string[] {
  if (task.tool !== "katana") throw new Error("Katana adapter received a non-Katana task");
  const proxy = buildPolicyProxyUrl(task);
  return ["-u", task.seed_url, "-jsonl", "-silent", "-no-color", "-disable-update-check", "-omit-body", "-omit-raw", "-disable-redirects", "-depth", String(budget.crawl_depth),
    "-timeout", String(Math.ceil(budget.request_timeout_seconds)), "-retry", "0", "-rate-limit", String(Math.floor(budget.requests_per_second)),
    "-host-rate-limit", String(Math.floor(budget.per_host_requests_per_second)), "-concurrency", "1", "-max-domain-pages", String(budget.unique_urls),
    "-max-response-size", String(budget.max_response_bytes), "-crawl-duration", `${Math.ceil(budget.wall_clock_seconds)}s`, "-crawl-scope", scope.host,
    "-proxy", proxy];
}
