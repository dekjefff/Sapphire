export const REASON_CODE_CATALOG = {
  generated_content_skipped: { domain: "intake", coverage_impact: "incomplete", message: "Known generated or dependency content was skipped." },
  intake_link_skipped: { domain: "intake", coverage_impact: "incomplete", message: "A filesystem or archive link was skipped safely." },
  intake_unsafe_entry: { domain: "intake", coverage_impact: "rejected", message: "The archive contains an unsupported or unsafe entry." },
  intake_archive_malformed: { domain: "intake", coverage_impact: "rejected", message: "The archive could not be read safely." },
  intake_limit_exceeded: { domain: "intake", coverage_impact: "rejected", message: "The source exceeds an intake limit." },
  route_parser_limit: { domain: "intake", coverage_impact: "incomplete", message: "Route parsing reached a configured limit." },
  route_source_parse_warning: { domain: "intake", coverage_impact: "incomplete", message: "Some source routes could not be parsed." },
  route_mount_dynamic: { domain: "intake", coverage_impact: "incomplete", message: "A dynamic route mount could not be resolved statically." },
  route_mount_unresolved: { domain: "intake", coverage_impact: "incomplete", message: "A route mount could not be resolved." },
  routes_none: { domain: "intake", coverage_impact: "none", message: "No source routes were identified." },
  scope_invalid: { domain: "discovery", coverage_impact: "incomplete", message: "The approved discovery scope is invalid." },
  scope_expired: { domain: "discovery", coverage_impact: "incomplete", message: "The approved discovery scope has expired." },
  scope_https_prefix_unsupported: { domain: "discovery", coverage_impact: "incomplete", message: "HTTPS discovery requires approval for the whole origin." },
  scope_path_denied: { domain: "discovery", coverage_impact: "incomplete", message: "The requested path is outside the approved scope." },
  scope_origin_denied: { domain: "discovery", coverage_impact: "incomplete", message: "The requested origin is outside the approved scope." },
  dns_policy_rejected: { domain: "discovery", coverage_impact: "incomplete", message: "The resolved destination did not satisfy network policy." },
  peer_ip_mismatch: { domain: "discovery", coverage_impact: "incomplete", message: "The connected peer did not match the approved address set." },
  redirect_denied: { domain: "discovery", coverage_impact: "incomplete", message: "A redirect was observed and not followed." },
  crawl_depth_exhausted: { domain: "discovery", coverage_impact: "incomplete", message: "The crawl reached its depth limit." },
  url_budget_exhausted: { domain: "discovery", coverage_impact: "incomplete", message: "The crawl reached its URL limit." },
  byte_budget_exhausted: { domain: "discovery", coverage_impact: "incomplete", message: "The crawl reached its response byte limit." },
  rate_budget_exhausted: { domain: "discovery", coverage_impact: "incomplete", message: "The crawl reached its request rate limit." },
  concurrency_budget_exhausted: { domain: "discovery", coverage_impact: "incomplete", message: "The crawl reached its concurrency limit." },
  timeout: { domain: "discovery", coverage_impact: "incomplete", message: "Discovery exceeded its time limit." },
  cancelled: { domain: "discovery", coverage_impact: "incomplete", message: "Discovery was cancelled." },
  tool_failed: { domain: "discovery", coverage_impact: "incomplete", message: "A discovery tool did not complete successfully." },
  malformed_tool_output: { domain: "discovery", coverage_impact: "incomplete", message: "A discovery tool returned invalid output." },
  parser_limitation: { domain: "discovery", coverage_impact: "incomplete", message: "The discovery parser could not fully interpret the result." },
  unresolved_route: { domain: "discovery", coverage_impact: "incomplete", message: "A runtime endpoint matched multiple source route candidates." },
  scope_limited: { domain: "discovery", coverage_impact: "incomplete", message: "The approved scope limited discovery coverage." },
  route_matched: { domain: "discovery", coverage_impact: "none", message: "The runtime endpoint matched a source route." },
  no_source_route_match: { domain: "discovery", coverage_impact: "incomplete", message: "The runtime endpoint did not match an identified source route." },
  source_only_not_observed: { domain: "discovery", coverage_impact: "incomplete", message: "The source route was not observed during this bounded crawl." },
  policy_limited: { domain: "discovery", coverage_impact: "incomplete", message: "The approved scope limited discovery coverage." },
} as const;

export type ReasonCode = keyof typeof REASON_CODE_CATALOG;
export type ReasonDomain = (typeof REASON_CODE_CATALOG)[ReasonCode]["domain"];

export function isReasonCode(value: unknown): value is ReasonCode {
  return typeof value === "string" && Object.hasOwn(REASON_CODE_CATALOG, value);
}

export function getReasonCode(value: unknown): (typeof REASON_CODE_CATALOG)[ReasonCode] | undefined {
  return isReasonCode(value) ? REASON_CODE_CATALOG[value] : undefined;
}
