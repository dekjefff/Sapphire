export type ServiceStatus = 'ok' | 'unavailable';
export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface HealthResponse {
  status: 'ok' | 'degraded';
  services: Record<string, ServiceStatus>;
}

export interface AssessmentInput {
  project_name: string;
  repository_path: string;
  target_url: string;
  source_type: 'local_path' | 'zip';
  source_file?: File;
  runtime_discovery_authorized: boolean;
}

export interface AssessmentCreated {
  assessment_id: string;
  job_id: string;
  status: JobStatus;
  runtime_discovery?: { status: 'authorized' | 'not_authorized'; detail: string };
}

export interface Assessment {
  id: string;
  project_name: string;
  repository_path: string;
  target_url: string;
  source_type: 'local_path' | 'zip' | null;
  source_identity_type?: 'git_commit' | 'content_sha256' | null;
  source_identity?: string | null;
  source_file_count?: number | null;
  source_total_bytes?: number | null;
  intake_status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  route_count?: number;
  technologies?: { name: string; category: string; confidence: number; evidence: string[] }[];
  routes?: {
    method: string;
    path: string;
    source_file: string;
    source_line: number | null;
    confidence: number;
  }[];
  findings?: { severity: 'warning' | 'error'; code: string; message: string }[];
  status: JobStatus;
  coverage_status: 'pending' | 'complete' | 'incomplete';
  created_at: string;
  normalized_finding_count?: number;
  severity_counts?: Partial<
    Record<'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown', number>
  >;
  job?: {
    id: string;
    tool: string;
    status: JobStatus;
    coverage_status: string;
    tool_version: string | null;
    adapter_version: string | null;
    config_id: string | null;
    config_sha256: string | null;
    exit_code: number | null;
    error: string | null;
    cancel_requested: boolean;
    started_at?: string | null;
    finished_at?: string | null;
    failure_reason_code?: string | null;
    counters?: Record<string, number>;
    provenance?: Record<string, unknown>;
  }[];
  artifacts?: {
    id: string;
    tool_run_id: string;
    artifact_kind: string;
    sha256: string;
    byte_size: number;
    metadata: Record<string, unknown>;
  }[];
  finding_groups?: {
    id: string;
    fingerprint: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
    duplicate_count: number;
    findings: {
      id: string;
      tool_run_id: string;
      artifact_id: string;
      raw_pointer: string;
      finding_type: string;
      rule_id: string | null;
      cve_id: string | null;
      title: string;
      message: string;
      severity: string;
      confidence: number | null;
      source_file: string | null;
      start_line: number | null;
      start_column: number | null;
      evidence: Record<string, unknown>;
    }[];
  }[];
  discovery?: {
    state:
      | 'not_authorized'
      | 'pending'
      | 'running'
      | 'complete'
      | 'incomplete'
      | 'failed'
      | 'cancelled'
      | 'empty';
    scope: null | {
      scheme: 'http' | 'https';
      host: string;
      port: number;
      path_mode: 'whole_origin' | 'prefix';
      path_prefixes: string[];
      policy_revision: string;
      policy_sha256: string;
      authorized_at: string;
      expires_at: string;
    };
    budget?: {
      profile_id: string;
      crawl_depth: number;
      unique_urls: number;
      global_concurrency: number;
      per_host_concurrency: number;
      requests_per_second: number;
      per_host_requests_per_second: number;
      connect_timeout_seconds: number;
      request_timeout_seconds: number;
      retries: number;
      max_response_bytes: number;
      total_response_bytes: number;
      wall_clock_seconds: number;
    };
    counts: Record<'matched' | 'source_only' | 'runtime_only' | 'unresolved', number>;
    reason_counts: Record<string, number>;
    endpoint_count: number;
    match_count: number;
    endpoints: {
      items: DiscoveryEndpoint[];
      limit: number;
      cursor: number;
      next_cursor: number | null;
    };
    matches: { items: DiscoveryMatch[]; limit: number; cursor: number; next_cursor: number | null };
  };
}

export interface DiscoveryEndpoint {
  id: string;
  tool_run_id: string;
  artifact_id: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  method: string;
  status_code: number | null;
  content_type: string | null;
  content_length: number | null;
  first_seen_at: string;
  last_seen_at: string;
  tool_version: string;
  config_sha256: string;
  scope_policy_sha256: string;
}

export interface DiscoveryMatch {
  id: string;
  runtime_endpoint_id: string | null;
  coverage_class: 'matched' | 'source_only' | 'runtime_only' | 'unresolved';
  source_method: string | null;
  source_route: string | null;
  source_file: string | null;
  source_line: number | null;
  candidate_source_route_ids: string[];
  reason_code: string;
  evidence: {
    artifact_id?: string;
    raw_pointer?: string | null;
    tool_run_id?: string;
    scope_policy_sha256?: string;
    source_route_id?: string;
  };
}
