'use client';

import { useEffect, useId, useState, type CSSProperties } from 'react';
import { fetchProjectReview } from '@/lib/api';
import type { ProjectReviewDetail, ProjectReviewSummary } from '@/lib/types';
import { ReviewFindings } from './review-findings';
import styles from './review-workspace.module.css';

export const reviewStatusLabels: Record<ProjectReviewSummary['status'], string> = {
  waiting_for_scans: 'Waiting for static scans',
  queued: 'Queued',
  running: 'Reviewing source',
  completed: 'Completed',
  incomplete: 'Incomplete',
  cancelled: 'Cancelled',
};

const filePageSize = 30;
const retryableReasons = new Set([
  'not_started',
  'partially_reviewed',
  'time_budget',
  'request_budget',
  'token_budget',
  'model_rate_limited',
]);
const reasonLabels: Record<string, string> = {
  continuing_review: 'Progress saved. Review will continue automatically.',
  waiting_for_provider: 'Progress saved. Waiting for the AI service before continuing.',
  project_budget:
    'The review reached its overall project limit. Saved results are available below.',
  cancelled: 'Review was cancelled.',
  not_started: 'Waiting for review',
  partially_reviewed: 'Only part of this file was reviewed',
  time_budget: 'The review reached its time limit.',
  request_budget: 'The review reached its request limit.',
  token_budget: 'The review reached its token limit.',
  file_size_limit: 'This file exceeds the review size limit.',
  line_size_limit: 'A line exceeds the review size limit.',
  source_unavailable: 'Unable to read this source file.',
  model_authentication_failed:
    'The AI service needs a valid connection. Contact your workspace administrator.',
  model_not_configured: 'The AI service has not been configured.',
  model_rate_limited:
    'The AI service reached its usage limit. Results saved so far are available below.',
  model_invalid_response: 'The AI response could not be verified.',
  invalid_model_report: 'The AI response could not be verified.',
  invalid_model_citation: 'Some source references could not be verified.',
  model_response_truncated: 'The AI did not return a complete response.',
  model_response_rejected: 'The AI did not review this section.',
  no_supported_source_files: 'There are no supported source files to review.',
  file_coverage_incomplete:
    'Some files could not be fully reviewed. Results saved so far are available below.',
};

const labelReason = (reason: string) =>
  Object.hasOwn(reasonLabels, reason)
    ? reasonLabels[reason]
    : 'This part of the review could not finish. Any saved results are available below.';

export function ProjectCodeReview({
  assessmentId,
  projectName,
  summary,
}: {
  assessmentId: string;
  projectName: string;
  summary: ProjectReviewSummary;
}) {
  const [report, setReport] = useState<ProjectReviewDetail | null>(null);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let current = true;
    void fetchProjectReview(assessmentId)
      .then(({ review }) => {
        if (!current) return;
        setReport(review);
        setError('');
      })
      .catch((cause: unknown) => {
        if (current)
          setError(cause instanceof Error ? cause.message : 'Could not load AI Code Review');
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [assessmentId, summary.updated_at, attempt]);

  const result = report?.report;
  const active = ['waiting_for_scans', 'queued', 'running'].includes(summary.status);
  const files = [
    ...(result?.pending_files ?? []).map(({ file, reason }) => ({
      file,
      detail: labelReason(reason),
      status:
        reason === 'cancelled' || summary.status === 'cancelled'
          ? 'Cancelled'
          : active && retryableReasons.has(reason)
            ? reason === 'partially_reviewed'
              ? 'Partial'
              : 'Queued'
            : 'Incomplete',
    })),
    ...(result?.reviewed_files ?? []).map((file) => ({
      file,
      detail: 'This file was fully reviewed.',
      status: 'Completed',
    })),
  ];
  const lastPage = Math.max(0, Math.ceil(files.length / filePageSize) - 1);
  const activePage = Math.min(lastPage, page);

  return (
    <>
      <section className={styles.surface} aria-labelledby="review-queue">
        <div className={styles.header}>
          <div>
            <h2 id="review-queue">{projectName}</h2>
            <p className={styles.muted}>
              {summary.total_files === null
                ? 'Source file count unavailable'
                : `${summary.reviewed_files ?? 0} / ${summary.total_files} files reviewed`}
            </p>
          </div>
          <span className={styles.status} data-status={summary.status}>
            {reviewStatusLabels[summary.status]}
          </span>
        </div>
        {summary.reason && <p role="status">{labelReason(summary.reason)}</p>}
        {error && (
          <div role="alert">
            <p>{error}</p>
            <button
              className={styles.control}
              type="button"
              onClick={() => setAttempt(attempt + 1)}
            >
              Retry
            </button>
          </div>
        )}
        {loading && <p role="status">Loading review…</p>}
        <h3>File queue</h3>
        {files.length ? (
          <>
            <ul className={styles.queue}>
              {files
                .slice(activePage * filePageSize, (activePage + 1) * filePageSize)
                .map(({ file, detail, status }, index) => (
                  <QueueRow key={file} file={file} detail={detail} status={status} index={index} />
                ))}
            </ul>
            {lastPage > 0 && (
              <div className={styles.pagination}>
                <button
                  className={styles.control}
                  type="button"
                  disabled={activePage === 0}
                  onClick={() => setPage(activePage - 1)}
                >
                  Previous
                </button>
                <span>
                  Page {activePage + 1} of {lastPage + 1}
                </span>
                <button
                  className={styles.control}
                  type="button"
                  disabled={activePage === lastPage}
                  onClick={() => setPage(activePage + 1)}
                >
                  Next
                </button>
              </div>
            )}
          </>
        ) : (
          !loading &&
          !error && (
            <p className={styles.muted}>
              {active ? 'Waiting for file progress from the review.' : 'No pending files reported.'}
            </p>
          )
        )}
      </section>
      <section className={styles.surface} aria-labelledby="review-report">
        <h2 id="review-report">Review report</h2>
        {report?.static_report && (
          <details className={styles.note}>
            <summary>Static scan · {report.static_report.finding_count} findings</summary>
            <ul>
              {report.static_report.tools.map(({ tool, status }) => (
                <li key={tool}>
                  {tool} · {status}
                </li>
              ))}
            </ul>
            {report.static_report.intake_gap_codes.length > 0 && (
              <p>Intake reported coverage gaps.</p>
            )}
          </details>
        )}
        {result ? (
          <>
            <p className={styles.muted}>
              {result.model} · {result.excluded_files} excluded files
            </p>
            <ReviewFindings findings={result.findings} />
            {result.coverage_gaps.length > 0 && (
              <details className={styles.note}>
                <summary>Coverage notes ({result.coverage_gaps.length})</summary>
                <ul>
                  {result.coverage_gaps.map((gap, index) => (
                    <li key={index}>{gap}</li>
                  ))}
                </ul>
              </details>
            )}
          </>
        ) : (
          !loading && !error && <p className={styles.muted}>No saved AI report yet.</p>
        )}
      </section>
    </>
  );
}

function QueueRow({
  file,
  detail,
  status,
  index,
}: {
  file: string;
  detail: string;
  status: string;
  index: number;
}) {
  const panelId = useId();
  const [open, setOpen] = useState(false);
  const active = status === 'Queued' || status === 'Partial';

  return (
    <li
      className={styles.queueRow}
      style={{ '--entry-delay': `${Math.min(index, 8) * 80}ms` } as CSSProperties}
    >
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen(!open)}
      >
        <span
          className={styles.queueIcon}
          data-active={active}
          data-status={status.toLowerCase()}
          aria-hidden="true"
        >
          {active || status === 'Completed' ? '' : '–'}
        </span>
        <code>{file}</code>
        <span className={styles.status} data-status={status.toLowerCase()}>
          {status}
        </span>
        <span className={styles.chevron} aria-hidden="true" />
      </button>
      <div id={panelId} aria-hidden={!open} data-open={open} className={styles.queueDetail}>
        <div>
          <p>{detail}</p>
        </div>
      </div>
    </li>
  );
}
