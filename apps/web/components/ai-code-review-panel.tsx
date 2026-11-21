'use client';

import { useState, type ChangeEvent } from 'react';
import { CodeReviewForm } from './code-review-form';
import {
  maxCodeReviewReportBytes,
  parseCodeReviewReport,
  type CodeReviewReport,
} from '@/lib/code-review-report';
import type { Assessment } from '@/lib/types';
import styles from './ai-code-review-panel.module.css';

type ImportState =
  | { status: 'empty' | 'loading' }
  | { status: 'error'; message: string }
  | { status: 'loaded'; fileName: string; report: CodeReviewReport };

const dependencyLabels = {
  clean: 'No advisories found',
  findings: 'Advisories found',
  incomplete: 'Incomplete',
};

export function AiCodeReviewPanel({ assessments }: { assessments: Assessment[] }) {
  const [state, setState] = useState<ImportState>({ status: 'empty' });

  async function importReport(event: ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;
    input.value = '';
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
      <h2 id="ai-review-title">AI Code Review</h2>
      <CodeReviewForm
        assessments={assessments}
        onReport={(report, label) => setState({ status: 'loaded', fileName: label, report })}
      />
      <h3 className={styles.importHeading}>Open a CLI report</h3>
      <p id="ai-review-help">The imported file stays in this tab.</p>
      <div className={styles.controls}>
        <label className={styles.fileInput}>
          <span>Report file</span>
          <input
            type="file"
            accept=".json,application/json"
            aria-describedby="ai-review-help"
            disabled={state.status === 'loading'}
            onChange={(event) => void importReport(event)}
          />
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
        <strong>{report.status === 'reviewed' ? 'Review completed' : 'Review incomplete'}</strong>
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
            {audit ? dependencyLabels[audit.status] : 'Unavailable'}
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
          {report.findings.length > 0 ? (
            <>
              <p>Verify each finding against the source before making changes.</p>
              <ul className={styles.findings}>
                {report.findings.map((finding, index) => (
                  <li key={index}>
                    <div className={styles.findingHeading}>
                      <strong>{finding.title}</strong>
                      <span>{finding.severity}</span>
                    </div>
                    <code>
                      {finding.file}:{finding.line}
                    </code>
                    <pre>{finding.evidence}</pre>
                    <p>{finding.remediation}</p>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p>The model reported no findings in the selected files.</p>
          )}
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
