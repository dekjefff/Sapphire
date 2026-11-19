'use client';

import { useState, type FormEvent } from 'react';
import { fetchCodeReview, submitCodeReview } from '@/lib/api';
import { validateCodeReviewReport, type CodeReviewReport } from '@/lib/code-review-report';
import type { Assessment } from '@/lib/types';
import styles from './ai-code-review-panel.module.css';

async function readFile(file: File, maxBytes: number) {
  if (file.size === 0 || file.size > maxBytes) {
    throw new Error(`${file.name} must be nonempty and no larger than ${maxBytes / 1024} KiB.`);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
}

type Props = {
  assessments: Assessment[];
  onReport: (report: CodeReviewReport, label: string) => void;
};

export function CodeReviewForm({ assessments, onReport }: Props) {
  const [assessmentId, setAssessmentId] = useState('');
  const [busy, setBusy] = useState<'running' | 'loading' | null>(null);
  const [error, setError] = useState('');
  const selected = assessments.find((assessment) => assessment.id === assessmentId);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || busy) return;
    const fields = new FormData(event.currentTarget);
    const manifest = fields.get('manifest');
    const lockfile = fields.get('lockfile');
    const sources = fields
      .getAll('source')
      .filter((file): file is File => file instanceof File && file.name !== '');
    setError('');
    setBusy('running');
    try {
      if (
        !(manifest instanceof File) ||
        manifest.name !== 'package.json' ||
        !(lockfile instanceof File) ||
        lockfile.name !== 'package-lock.json'
      ) {
        throw new Error('Select package.json and package-lock.json from the same npm package.');
      }
      if (sources.length === 0 || sources.length > 8 || fields.get('share') !== 'on') {
        throw new Error('Choose 1–8 source files and confirm sharing.');
      }
      const response = await submitCodeReview(selected.id, {
        share_with_providers: true,
        manifest: await readFile(manifest, 64 * 1024),
        lockfile: await readFile(lockfile, 1024 * 1024),
        sources: await Promise.all(
          sources.map(async (file) => ({
            name: file.name,
            text: await readFile(file, 8 * 1024),
          })),
        ),
      });
      onReport(validateCodeReviewReport(response.report), selected.project_name);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to run AI Code Review.');
    } finally {
      setBusy(null);
    }
  }

  async function loadSaved() {
    if (!selected || busy) return;
    setError('');
    setBusy('loading');
    try {
      const response = await fetchCodeReview(selected.id);
      onReport(validateCodeReviewReport(response.report), selected.project_name);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load the saved report.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <form onSubmit={(event) => void handleSubmit(event)}>
      <p>Run both review passes on files you select, and save the result with an assessment.</p>
      {assessments.length === 0 ? (
        <p>Create an assessment first to run a review from this page.</p>
      ) : (
        <fieldset className={styles.reviewFields} disabled={busy !== null}>
          <legend>Run with Groq</legend>
          <label className={styles.fileInput}>
            <span>Assessment</span>
            <select
              value={assessmentId}
              required
              onChange={(event) => {
                setAssessmentId(event.target.value);
                setError('');
              }}
            >
              <option value="">Select an assessment</option>
              {assessments.map((assessment) => (
                <option key={assessment.id} value={assessment.id}>
                  {assessment.project_name} · {assessment.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
          <div className={styles.reviewInputs}>
            <label className={styles.fileInput}>
              <span>package.json</span>
              <input name="manifest" type="file" accept=".json" required />
            </label>
            <label className={styles.fileInput}>
              <span>package-lock.json</span>
              <input name="lockfile" type="file" accept=".json" required />
            </label>
            <label className={styles.fileInput}>
              <span>Source files (1–8, up to 8 KiB each)</span>
              <input
                name="source"
                type="file"
                accept=".ts,.tsx,.js,.jsx,.mts,.cts,.mjs,.cjs,.py,.go,.java,.cs,.rs,.rb,.php"
                multiple
                required
              />
            </label>
          </div>
          <label className={styles.consent}>
            <input name="share" type="checkbox" required />
            <span>
              I approve sharing dependency metadata with npm and the selected source files with
              Groq, and saving the report and cited lines to this assessment.
            </span>
          </label>
          <div className={styles.controls}>
            <button type="submit" className={styles.runButton} disabled={!selected}>
              Run AI Code Review
            </button>
            <button type="button" disabled={!selected} onClick={() => void loadSaved()}>
              Open latest saved review
            </button>
          </div>
        </fieldset>
      )}
      {busy && (
        <p role="status">
          {busy === 'running'
            ? 'Checking dependencies and reviewing selected files…'
            : 'Loading saved review…'}
        </p>
      )}
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
    </form>
  );
}
