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
}

export interface AssessmentCreated {
  assessment_id: string;
  job_id: string;
  status: JobStatus;
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
  routes?: { method: string; path: string; source_file: string; source_line: number | null; confidence: number }[];
  findings?: { severity: 'warning' | 'error'; code: string; message: string }[];
  status: JobStatus;
  coverage_status: 'pending' | 'complete' | 'incomplete';
  created_at: string;
  normalized_finding_count?: number;
  severity_counts?: Partial<Record<'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown', number>>;
  job?: { id: string; tool: string; status: JobStatus; coverage_status: string; tool_version: string | null; adapter_version: string | null; config_id: string | null; config_sha256: string | null; exit_code: number | null; error: string | null; cancel_requested: boolean; provenance?: Record<string, unknown> }[];
  artifacts?: { id: string; tool_run_id: string; artifact_kind: string; sha256: string; byte_size: number; metadata: Record<string, unknown> }[];
  finding_groups?: {
    id: string; fingerprint: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'; duplicate_count: number;
    findings: { id: string; tool_run_id: string; artifact_id: string; raw_pointer: string; finding_type: string; rule_id: string | null; cve_id: string | null; title: string; message: string; severity: string; confidence: number | null; source_file: string | null; start_line: number | null; start_column: number | null; evidence: Record<string, unknown> }[];
  }[];
}
