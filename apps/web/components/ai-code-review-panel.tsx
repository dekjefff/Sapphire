'use client';

import { useState } from 'react';
import {
  maxCodeReviewReportBytes,
  parseCodeReviewReport,
  type CodeReviewReport,
} from '@/lib/code-review-report';
import { ReviewFindings } from './review-findings';
import { StatusPill } from './status-pill';
import styles from './ai-code-review-panel.module.css';

type ImportState =
  | { status: 'empty' | 'loading' }
  | { status: 'error'; message: string }
  | { status: 'loaded'; fileName: string; report: CodeReviewReport };

const dependencyLabels = {
  clean: 'No advisories found',
  findings: 'Advisories found',
};

export function AiCodeReviewPanel() {
  const [state, setState] = useState<ImportState>({ status: 'empty' });

  async function importReport(files: FileList | null) {
    const file = files?.[0];
    if (!file) return;
    if (files.length !== 1) {
      setState({ status: 'error', message: 'Choose one JSON report.' });
      return;
    }
    setState({ status: 'loading' });
    try {
      if (file.size > maxCodeReviewReportBytes) {
        throw new Error('Choose a report smaller than 128 KiB.');
      }
      const report = parseCodeReviewReport(new Uint8Array(await file.arrayBuffer()));
      setState({ status: 'loaded', fileName: file.name, report });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to open this report.';
      setState({ status: 'error', message });
    }
  }

  return (
    <section className={styles.panel} aria-labelledby="ai-review-title">
      <h2 id="ai-review-title">Open a CLI report</h2>
      <div className={styles.controls}>
        <label className={styles.dropZone}>
          <input
            type="file"
            aria-label="Browse files"
            accept=".json,application/json"
            aria-describedby="ai-review-help"
            disabled={state.status === 'loading'}
            onChange={(event) => {
              void importReport(event.currentTarget.files);
              event.currentTarget.value = '';
            }}
            onDragOver={(event) => {
              if (event.dataTransfer.types.includes('Files')) event.preventDefault();
            }}
            onDrop={(event) => {
              event.preventDefault();
              if (state.status !== 'loading') void importReport(event.dataTransfer.files);
            }}
          />
          <span className={styles.browse} aria-hidden="true">
            Browse files
          </span>
          <span className={styles.dropCopy}>
            <strong>Choose a Sapphire CLI report</strong>
            <span id="ai-review-help">Upload a local JSON report to inspect its findings.</span>
          </span>
        </label>
        {state.status === 'loaded' && (
          <button type="button" onClick={() => setState({ status: 'empty' })}>
            Clear report
          </button>
        )}
      </div>
      {state.status === 'loading' && <p role="status">Reading report…</p>}
      {state.status === 'error' && (
        <p className={styles.error} role="alert">
          {state.message}
        </p>
      )}
      {state.status === 'loaded' && (
        <ReviewResult fileName={state.fileName} report={state.report} />
      )}
    </section>
  );
}

function ReviewResult({ fileName, report }: { fileName: string; report: CodeReviewReport }) {
  const audit = report.dependency_audit;
  return (
    <div className={styles.result}>
      <p className={styles.resultStatus} role="status">
        {report.status === 'reviewed' ? (
          <strong>Review completed</strong>
        ) : (
          <StatusPill status="incomplete" label="Review incomplete" />
        )}
        <span>{fileName}</span>
      </p>
      <dl className={styles.metadata}>
        {report.status === 'reviewed' ? (
          <div>
            <dt>Model</dt>
            <dd>{report.model}</dd>
          </div>
        ) : (
          <div>
            <dt>Reason</dt>
            <dd>{report.reason.replaceAll('_', ' ')}</dd>
          </div>
        )}
        <div>
          <dt>Dependency audit</dt>
          <dd>
            {audit?.status === 'incomplete' ? (
              <StatusPill status="incomplete" />
            ) : audit ? (
              dependencyLabels[audit.status]
            ) : (
              'Unavailable'
            )}
            {audit?.status === 'findings' && ` (${audit.finding_count})`}
          </dd>
          {audit?.reason && <dd>{audit.reason.replaceAll('_', ' ')}</dd>}
        </div>
        {audit && (
          <div>
            <dt>Lockfile match in report</dt>
            <dd>{audit.lockfile_verified ? 'Verified' : 'Unverified'}</dd>
          </div>
        )}
      </dl>
      {report.status === 'reviewed' && (
        <>
          <details className={styles.details}>
            <summary>Reviewed files ({report.reviewed_files.length})</summary>
            <ul>
              {report.reviewed_files.map((file, index) => (
                <li key={index}>
                  <code>{file}</code>
                </li>
              ))}
            </ul>
          </details>
          <h3>Model findings ({report.findings.length})</h3>
          <ReviewFindings findings={report.findings} />
          {report.coverage_gaps.length > 0 && (
            <details className={styles.details} open>
              <summary>Reported coverage gaps ({report.coverage_gaps.length})</summary>
              <ul>
                {report.coverage_gaps.map((gap, index) => (
                  <li key={index}>{gap}</li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  );
}
