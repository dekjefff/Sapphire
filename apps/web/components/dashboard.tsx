'use client';

import { useState } from 'react';
import { AppShell } from './app-shell';
import { AssessmentList } from './assessment-list';
import { NewAssessmentForm } from './new-assessment-form';
import { ServiceHealth } from './service-health';
import { useAssessments } from '@/hooks/use-assessments';
import type { AssessmentInput } from '@/lib/types';
import styles from './dashboard.module.css';

export function Dashboard() {
  const { health, assessments, loadError, refresh, createAssessment } = useAssessments();
  const [submissionError, setSubmissionError] = useState('');
  const [submissionMessage, setSubmissionMessage] = useState('');

  async function handleCreate(input: AssessmentInput) {
    setSubmissionError('');
    setSubmissionMessage('');
    try {
      const created = await createAssessment(input);
      setSubmissionMessage(`Assessment ${created.assessment_id} queued · job ${created.job_id}`);
    } catch (error) {
      setSubmissionError(error instanceof Error ? error.message : 'Request failed');
    }
  }

  return (
    <AppShell>
      <div className={styles.pageHeading}>
        <div>
          <p className={styles.eyebrow}>SECURITY WORKSPACE</p>
          <h1>Assessments</h1>
          <p className={styles.subtitle}>Set up a scoped assessment and follow its job status.</p>
        </div>
        <div className={styles.milestone}>FOUNDATION · MILESTONE 0</div>
      </div>

      <ServiceHealth health={health} />
      {loadError && (
        <p className={styles.loadError} role="status">
          {loadError}
        </p>
      )}

      <div className={styles.mainGrid}>
        <NewAssessmentForm
          disabled={health?.status !== 'ok'}
          error={submissionError}
          message={submissionMessage}
          onCreate={handleCreate}
        />
        <AssessmentList assessments={assessments} onRefresh={() => void refresh()} />
      </div>

      <footer className={styles.footer}>
        <span>Sapphire local workspace</span>
        <span>Jobs run as a deterministic dummy worker in this milestone.</span>
      </footer>
    </AppShell>
  );
}
