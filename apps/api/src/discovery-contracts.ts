import { z } from "zod";
import { REASON_CODE_CATALOG, type ReasonCode } from "./reason-codes.js";

export const DISCOVERY_SCHEMA_VERSION = 1 as const;

export const DiscoveryMethods = ["GET"] as const;
export const DiscoveryPathModes = ["whole_origin", "prefix"] as const;
export const DiscoveryRunStatuses = ["queued", "running", "completed", "failed", "cancelled"] as const;
export const DiscoveryCoverageStatuses = ["pending", "complete", "incomplete"] as const;
export const CoverageClasses = ["matched", "source_only", "runtime_only", "unresolved"] as const;
export const DiscoveryTools = ["httpx", "katana"] as const;

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const uuidSchema = z.string().uuid();
const timestampSchema = z.string().datetime({ offset: true });
const reasonCodeValues = Object.keys(REASON_CODE_CATALOG) as [ReasonCode, ...ReasonCode[]];
export const ReasonCodeSchema = z.enum(reasonCodeValues);

export const DiscoveryScopeSchema = z.object({
  scope_id: uuidSchema,
  assessment_id: uuidSchema,
  scheme: z.enum(["http", "https"]),
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535),
  path_mode: z.enum(DiscoveryPathModes),
  path_prefixes: z.array(z.string().min(1).max(2048)).max(100),
  allowed_methods: z.array(z.literal("GET")).length(1),
  pinned_ips: z.array(z.string().min(2).max(64)).min(1).max(32),
  policy_revision: z.string().min(1).max(64),
  policy_sha256: sha256Schema,
  authorization_actor: z.string().min(1).max(120),
  authorized_at: timestampSchema,
  expires_at: timestampSchema,
}).strict().superRefine((scope, ctx) => {
  if (scope.path_mode === "whole_origin" && scope.path_prefixes.length !== 0) {
    ctx.addIssue({ code: "custom", path: ["path_prefixes"], message: "whole_origin scopes cannot contain path prefixes" });
  }
  if (scope.path_mode === "prefix" && (scope.scheme !== "http" || scope.path_prefixes.length === 0)) {
    ctx.addIssue({ code: "custom", path: ["path_mode"], message: "prefix scopes require HTTP and at least one prefix" });
  }
  if (scope.expires_at <= scope.authorized_at) {
    ctx.addIssue({ code: "custom", path: ["expires_at"], message: "scope expiry must follow authorization" });
  }
  if (scope.host !== scope.host.toLowerCase() || scope.host.includes("*") || scope.host.endsWith(".")) {
    ctx.addIssue({ code: "custom", path: ["host"], message: "scope host must be canonical and exact" });
  }
  if (scope.path_prefixes.some((prefix) => !prefix.startsWith("/") || prefix.includes("?") || prefix.includes("#") || prefix.includes("\\"))) {
    ctx.addIssue({ code: "custom", path: ["path_prefixes"], message: "scope path prefixes must be normalized safe paths" });
  }
});
export type DiscoveryScope = z.infer<typeof DiscoveryScopeSchema>;

export const DiscoveryBudgetProfileSchema = z.object({
  profile_id: z.string().min(1).max(64),
  crawl_depth: z.number().int().min(0).max(3),
  unique_urls: z.number().int().min(1).max(500),
  global_concurrency: z.number().int().min(1).max(2),
  per_host_concurrency: z.literal(1),
  requests_per_second: z.number().positive().max(2),
  per_host_requests_per_second: z.number().positive().max(1),
  connect_timeout_seconds: z.number().positive().max(5),
  request_timeout_seconds: z.number().positive().max(10),
  retries: z.literal(0),
  max_response_bytes: z.number().int().positive().max(1_048_576),
  total_response_bytes: z.number().int().positive().max(52_428_800),
  wall_clock_seconds: z.number().positive().max(120),
}).strict();
export type DiscoveryBudgetProfile = z.infer<typeof DiscoveryBudgetProfileSchema>;

export const DEFAULT_DISCOVERY_BUDGET: DiscoveryBudgetProfile = Object.freeze({
  profile_id: "discovery-default-v1",
  crawl_depth: 3,
  unique_urls: 500,
  global_concurrency: 2,
  per_host_concurrency: 1,
  requests_per_second: 2,
  per_host_requests_per_second: 1,
  connect_timeout_seconds: 5,
  request_timeout_seconds: 10,
  retries: 0,
  max_response_bytes: 1_048_576,
  total_response_bytes: 52_428_800,
  wall_clock_seconds: 120,
});

export const DiscoveryTaskSchema = z.object({
  schema_version: z.literal(DISCOVERY_SCHEMA_VERSION),
  assessment_id: uuidSchema,
  tool_run_id: uuidSchema,
  scope_id: uuidSchema,
  scope_policy_sha256: sha256Schema,
  tool: z.enum(DiscoveryTools),
  seed_url: z.string().url().max(2048),
  budget_profile_id: z.string().min(1).max(64),
  cancellation_ref: z.string().min(1).max(128),
}).strict();
export type DiscoveryTask = z.infer<typeof DiscoveryTaskSchema>;

export const DiscoveryCountersSchema = z.object({
  urls_seen: z.number().int().nonnegative(),
  requests_sent: z.number().int().nonnegative(),
  responses_received: z.number().int().nonnegative(),
  response_bytes: z.number().int().nonnegative(),
  endpoints_persisted: z.number().int().nonnegative(),
  redirects_denied: z.number().int().nonnegative(),
  policy_denials: z.number().int().nonnegative(),
}).strict();
export type DiscoveryCounters = z.infer<typeof DiscoveryCountersSchema>;

export const DiscoveryArtifactDescriptorSchema = z.object({
  artifact_id: uuidSchema,
  artifact_kind: z.enum(["httpx_json", "katana_json"]),
  sha256: sha256Schema,
  byte_size: z.number().int().nonnegative(),
}).strict();
export type DiscoveryArtifactDescriptor = z.infer<typeof DiscoveryArtifactDescriptorSchema>;

export const DiscoveryResultSchema = z.object({
  schema_version: z.literal(DISCOVERY_SCHEMA_VERSION),
  assessment_id: uuidSchema,
  tool_run_id: uuidSchema,
  tool: z.enum(DiscoveryTools),
  tool_version: z.string().min(1).max(64),
  adapter_version: z.string().min(1).max(64),
  config_sha256: sha256Schema,
  scope_policy_sha256: sha256Schema,
  status: z.enum(DiscoveryRunStatuses),
  coverage_status: z.enum(DiscoveryCoverageStatuses),
  failure_reason_code: ReasonCodeSchema.nullable(),
  counters: DiscoveryCountersSchema,
  started_at: timestampSchema.nullable(),
  finished_at: timestampSchema.nullable(),
  artifacts: z.array(DiscoveryArtifactDescriptorSchema).max(2),
}).strict().superRefine((result, ctx) => {
  if (result.status === "completed" && result.coverage_status === "pending") {
    ctx.addIssue({ code: "custom", path: ["coverage_status"], message: "terminal runs cannot have pending coverage" });
  }
  if (result.status !== "completed" && result.coverage_status === "complete") {
    ctx.addIssue({ code: "custom", path: ["coverage_status"], message: "failed or cancelled runs have incomplete coverage" });
  }
});
export type DiscoveryResult = z.infer<typeof DiscoveryResultSchema>;

export const RuntimeEndpointSchema = z.object({
  endpoint_id: uuidSchema,
  assessment_id: uuidSchema,
  tool_run_id: uuidSchema,
  artifact_id: uuidSchema,
  scheme: z.enum(["http", "https"]),
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535),
  path: z.string().startsWith("/").max(2048),
  method: z.literal("GET"),
  status_code: z.number().int().min(100).max(599).nullable(),
  content_type: z.string().max(256).nullable(),
  content_length: z.number().int().nonnegative().nullable(),
  title: z.string().max(512).nullable(),
  referrer_path: z.string().startsWith("/").max(2048).nullable(),
  first_seen_at: timestampSchema,
  last_seen_at: timestampSchema,
  tool_version: z.string().min(1).max(64),
  config_sha256: sha256Schema,
  scope_policy_sha256: sha256Schema,
}).strict();
export type RuntimeEndpoint = z.infer<typeof RuntimeEndpointSchema>;

export const CoverageClassSchema = z.enum(CoverageClasses);
export type CoverageClass = z.infer<typeof CoverageClassSchema>;

export const SourceRouteIdSchema = z.string()
  .regex(/^[1-9][0-9]*$/)
  .refine((value) => BigInt(value) <= 9_223_372_036_854_775_807n, "source route ID exceeds BIGSERIAL range");
export type SourceRouteId = z.infer<typeof SourceRouteIdSchema>;

export const EndpointRouteMatchSchema = z.object({
  match_id: uuidSchema,
  assessment_id: uuidSchema,
  runtime_endpoint_id: uuidSchema.nullable(),
  coverage_class: CoverageClassSchema,
  source_method: z.literal("GET").nullable(),
  source_route: z.string().startsWith("/").max(2048).nullable(),
  source_file: z.string().max(2048).nullable(),
  source_line: z.number().int().positive().nullable(),
  candidate_source_route_ids: z.array(SourceRouteIdSchema).max(100),
  reason_code: ReasonCodeSchema,
  evidence: z.record(z.string(), z.unknown()),
}).strict().superRefine((match, ctx) => {
  if ((match.coverage_class === "matched" || match.coverage_class === "runtime_only") && !match.runtime_endpoint_id) {
    ctx.addIssue({ code: "custom", path: ["runtime_endpoint_id"], message: "runtime endpoint evidence is required" });
  }
  if (match.coverage_class === "source_only" && (!match.source_route || !match.source_method)) {
    ctx.addIssue({ code: "custom", path: ["source_route"], message: "source route evidence is required" });
  }
  if (match.coverage_class === "unresolved" && !match.runtime_endpoint_id && !match.source_route) {
    ctx.addIssue({ code: "custom", path: ["runtime_endpoint_id"], message: "unresolved matches require evidence" });
  }
});
export type EndpointRouteMatch = z.infer<typeof EndpointRouteMatchSchema>;
