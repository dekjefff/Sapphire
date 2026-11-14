'use client';

import { useCallback, useEffect, useState } from 'react';
import { fetchAssessments, fetchHealth, submitAssessment } from '@/lib/api';
import type { Assessment, AssessmentInput, HealthResponse } from '@/lib/types';

export function useAssessments() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loadError, setLoadError] = useState('');

  const refresh = useCallback(async () => {
    try {
      const [nextHealth, nextAssessments] = await Promise.all([fetchHealth(), fetchAssessments()]);
      setHealth(nextHealth);
      setAssessments(nextAssessments);
      setLoadError('');
    } catch (error) {
      setHealth(null);
      setLoadError(error instanceof Error ? error.message : 'Could not load workspace data');
    }
  }, []);

  const createAssessment = useCallback(
    async (input: AssessmentInput) => {
      const result = await submitAssessment(input);
      await refresh();
      return result;
    },
    [refresh],
  );

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  return { health, assessments, loadError, refresh, createAssessment };
}
