import type { Assessment, AssessmentCreated, AssessmentInput, HealthResponse } from './types';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      ...(init?.body && !(init.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
    cache: 'no-store',
  });

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
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
    body.append('target_url', input.target_url);
    if (input.source_file) body.append('source', input.source_file);
    return request<AssessmentCreated>('/assessments/zip', { method: 'POST', body });
  }
  return request<AssessmentCreated>('/assessments', {
    method: 'POST',
    body: JSON.stringify({ project_name: input.project_name, repository_path: input.repository_path, target_url: input.target_url, source_type: input.source_type }),
  });
}
