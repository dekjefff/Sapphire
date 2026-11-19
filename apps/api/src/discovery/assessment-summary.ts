import { DEFAULT_DISCOVERY_BUDGET } from "../discovery-contracts.js";

export type DiscoveryState = "failed" | "cancelled" | "running" | "pending" | "not_authorized" | "incomplete" | "empty" | "complete";
export type DiscoveryRunSummary = { status: string; coverage_status: string | null };

export function resolveDiscoveryState(runs: DiscoveryRunSummary[], endpointCount: number, scopeCount: number): DiscoveryState {
  if (runs.some((run) => run.status === "failed")) return "failed";
  if (runs.some((run) => run.status === "cancelled")) return "cancelled";
  if (runs.some((run) => run.status === "queued" || run.status === "running")) return "running";
  if (runs.length === 0) return scopeCount > 0 ? "pending" : "not_authorized";
  if (runs.some((run) => run.coverage_status === "incomplete")) return "incomplete";
  return endpointCount === 0 ? "empty" : "complete";
}

export function getDiscoveryBudgetDto() {
  return { ...DEFAULT_DISCOVERY_BUDGET };
}
