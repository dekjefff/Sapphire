import type {
  Assessment,
  AssessmentCreated,
  AssessmentInput,
  HealthResponse,
  PassiveCapture,
  ProjectReviewDetail,
  ProjectReviewCatalog,
  WorkspaceOverview,
} from './types';

export const API_URL = '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      ...(init?.body && !(init.body instanceof FormData)
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...init?.headers,
    },
    cache: 'no-store',
  });

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && typeof window !== 'undefined') window.location.replace('/login');
    const detail =
      body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string'
        ? body.detail
        : `Request failed with status ${response.status}`;
    throw new Error(detail);
  }

  return body as T;
}

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export function fetchAssessments(): Promise<Assessment[]> {
  return request<Assessment[]>('/assessments');
}

export function submitAssessment(input: AssessmentInput): Promise<AssessmentCreated> {
  if (input.source_type === 'zip') {
    const body = new FormData();
    body.append('project_name', input.project_name);
    if (input.target_url) body.append('target_url', input.target_url);
    body.append('runtime_discovery_authorized', String(input.runtime_discovery_authorized));
    body.append('ai_review_authorized', String(input.ai_review_authorized === true));
    if (input.ai_review_authorized && input.ai_review_provider) {
      body.append('ai_review_provider', input.ai_review_provider);
    }
    if (input.source_file) body.append('source', input.source_file);
    return request<AssessmentCreated>('/assessments/zip', { method: 'POST', body });
  }
  return request<AssessmentCreated>('/assessments', {
    method: 'POST',
    body: JSON.stringify({
      project_name: input.project_name,
      repository_path: input.repository_path,
      target_url: input.target_url,
      source_type: input.source_type,
      runtime_discovery_authorized: input.runtime_discovery_authorized,
    }),
  });
}

export function fetchAssessmentDetail(
  id: string,
  options: { limit?: number; endpointCursor?: number; matchCursor?: number } = {},
): Promise<Assessment> {
  const query = new URLSearchParams({
    limit: String(options.limit ?? 50),
    endpoint_cursor: String(options.endpointCursor ?? 0),
    match_cursor: String(options.matchCursor ?? 0),
  });
  return request<Assessment>(`/assessments/${encodeURIComponent(id)}?${query}`);
}

export function fetchLatestPassiveCapture(id: string): Promise<PassiveCapture | null> {
  return request<PassiveCapture | null>(
    `/assessments/${encodeURIComponent(id)}/passive-captures/latest`,
  );
}

export function importPassiveCapture(id: string, body: string): Promise<PassiveCapture> {
  return request<PassiveCapture>(`/assessments/${encodeURIComponent(id)}/passive-captures`, {
    method: 'POST',
    body,
  });
}

export function fetchProjectReview(id: string): Promise<{ review: ProjectReviewDetail | null }> {
  return request(`/assessments/${encodeURIComponent(id)}/project-code-review`);
}

export function controlProjectReview(id: string, action: 'pause' | 'resume' | 'stop') {
  return request<{ accepted: true }>(
    `/assessments/${encodeURIComponent(id)}/project-code-review/${action}`,
    { method: 'POST' },
  );
}

export function fetchWorkspaceOverview(signal?: AbortSignal) {
  return request<WorkspaceOverview>('/workspace/overview', { signal });
}

export function fetchReviewModels(signal?: AbortSignal) {
  return request<ProjectReviewCatalog>('/workspace/review-models', { signal });
}
