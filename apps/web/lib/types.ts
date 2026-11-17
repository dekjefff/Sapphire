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
  status: JobStatus;
  created_at: string;
  job?: { id: string; status: JobStatus } | null;
}
