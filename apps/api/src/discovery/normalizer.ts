import { randomUUID } from "node:crypto";
import { RuntimeEndpointSchema, type DiscoveryScope, type RuntimeEndpoint } from "../discovery-contracts.js";
import { parseHttpxJsonl, parseKatanaJsonl } from "./parsers.js";

export type NormalizedRuntimeEndpoint = { endpoint: RuntimeEndpoint; raw_pointer: string };

/** Normalize sanitized adapter JSONL into one GET endpoint per canonical URL per run. */
export function normalizeDiscoveryJsonl(input: string, args: {
  tool: "httpx" | "katana";
  assessmentId: string;
  toolRunId: string;
  artifactId: string;
  scope: DiscoveryScope;
  toolVersion: string;
  configSha256: string;
  observedAt: string;
}): NormalizedRuntimeEndpoint[] {
  const observations = args.tool === "httpx" ? parseHttpxJsonl(input, args.scope) : parseKatanaJsonl(input, args.scope);
  const seen = new Map<string, NormalizedRuntimeEndpoint>();
  observations.forEach((row, index) => {
    const url = new URL(row.url);
    const key = `${url.protocol}//${url.hostname.toLowerCase()}:${url.port || (url.protocol === "https:" ? "443" : "80")}${row.path}`;
    const prior = seen.get(key);
    if (prior) {
      prior.endpoint.last_seen_at = args.observedAt;
      if (prior.endpoint.status_code === null && row.status_code !== null) prior.endpoint.status_code = row.status_code;
      if (prior.endpoint.content_type === null && row.content_type !== null) prior.endpoint.content_type = row.content_type;
      if (prior.endpoint.content_length === null && row.content_length !== null) prior.endpoint.content_length = row.content_length;
      if (prior.endpoint.title === null && row.title !== null) prior.endpoint.title = row.title;
      if (prior.endpoint.referrer_path === null && row.referrer_path !== null) prior.endpoint.referrer_path = row.referrer_path;
      return;
    }
    const endpoint = RuntimeEndpointSchema.parse({
      endpoint_id: randomUUID(), assessment_id: args.assessmentId, tool_run_id: args.toolRunId,
      artifact_id: args.artifactId, scheme: url.protocol.slice(0, -1), host: url.hostname.toLowerCase(),
      port: Number(url.port || (url.protocol === "https:" ? 443 : 80)), path: row.path, method: "GET",
      status_code: row.status_code, content_type: row.content_type, content_length: row.content_length,
      title: row.title, referrer_path: row.referrer_path, first_seen_at: args.observedAt, last_seen_at: args.observedAt,
      tool_version: args.toolVersion, config_sha256: args.configSha256, scope_policy_sha256: args.scope.policy_sha256,
    });
    seen.set(key, { endpoint, raw_pointer: `/line/${index + 1}` });
  });
  return [...seen.values()];
}
