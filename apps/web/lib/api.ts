import type { Assessment, AssessmentCreated, AssessmentInput, HealthResponse } from './types';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
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
  return request<AssessmentCreated>('/assessments', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}
