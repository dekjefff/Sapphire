'use client';

import { useState, type FormEvent } from 'react';
import type { AssessmentInput } from '@/lib/types';
import styles from './new-assessment-form.module.css';

interface NewAssessmentFormProps {
  disabled: boolean;
  error: string;
  message: string;
  onCreate: (input: AssessmentInput) => Promise<void>;
}

const initialForm: AssessmentInput = {
  project_name: 'Juice Shop demo',
  repository_path: './samples/juice-shop',
  target_url: 'http://juiceshop:3000',
};

export function NewAssessmentForm({ disabled, error, message, onCreate }: NewAssessmentFormProps) {
  const [form, setForm] = useState(initialForm);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await onCreate(form);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className={styles.panel} aria-labelledby="new-assessment-title">
      <div className={styles.sectionHead}>
        <div className={styles.step} aria-hidden="true">
          01
        </div>
        <div>
          <h2 id="new-assessment-title">New assessment</h2>
          <p>Provide a project and an in-scope local target.</p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <label>
          Project name
          <input
            required
            maxLength={120}
            value={form.project_name}
            onChange={(event) => setForm({ ...form, project_name: event.target.value })}
            placeholder="e.g. Payments service"
          />
        </label>
        <label>
          Repository path
          <input
            required
            maxLength={2048}
            value={form.repository_path}
            onChange={(event) => setForm({ ...form, repository_path: event.target.value })}
            placeholder="Local path or repository reference"
          />
          <span className={styles.hint}>
            Recorded as project metadata; source intake is not enabled yet.
          </span>
        </label>
        <label>
          Target URL
          <input
            required
            type="url"
            value={form.target_url}
            onChange={(event) => setForm({ ...form, target_url: event.target.value })}
            placeholder="http://juiceshop:3000"
          />
          <span className={styles.hint}>
            Foundation scope accepts localhost or the isolated Juice Shop service.
          </span>
        </label>

        {error && (
          <div className={`${styles.notice} ${styles.error}`} role="alert">
            {error}
          </div>
        )}
        {message && (
          <div className={`${styles.notice} ${styles.success}`} role="status">
            {message}
          </div>
        )}
        <button className={styles.primaryButton} disabled={submitting || disabled} type="submit">
          {submitting ? 'Creating…' : 'Create assessment'}
          <span aria-hidden="true">→</span>
        </button>
      </form>
    </section>
  );
}
