'use client';

import { useEffect, useState } from 'react';
import { fetchProjectReview } from '@/lib/api';
import type { ProjectReviewDetail, ProjectReviewSummary } from '@/lib/types';
import styles from './ai-code-review-panel.module.css';

const labels: Record<ProjectReviewSummary['status'], string> = {
  waiting_for_scans: 'Waiting for static scans',
  queued: 'Queued',
  running: 'Reviewing source',
  completed: 'Completed',
  incomplete: 'Incomplete',
  cancelled: 'Cancelled',
};

const pendingPageSize = 30;
const labelReason = (reason: string) => reason.replaceAll('_', ' ');

export function ProjectCodeReview({
  assessmentId,
  summary,
}: {
  assessmentId: string;
  summary: ProjectReviewSummary;
}) {
  const [open, setOpen] = useState(false);
  const [report, setReport] = useState<ProjectReviewDetail | null>(null);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);

  useEffect(() => {
    if (!open) return;
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
      });
    return () => {
      current = false;
    };
  }, [assessmentId, open, summary.updated_at]);

  const pending = report?.report?.pending_files ?? [];
  const lastPage = Math.max(0, Math.ceil(pending.length / pendingPageSize) - 1);
  const activePage = Math.min(lastPage, page);
  const findings = report?.report?.findings ?? [];
  return (
    <details
      className={styles.details}
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        AI Code Review · {labels[summary.status]}
        {summary.total_files !== null &&
          ` · ${summary.reviewed_files ?? 0}/${summary.total_files} files`}
      </summary>
      {summary.reason && <p role="status">{labelReason(summary.reason)}</p>}
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
      {!report && !error && open && <p role="status">Loading AI Code Review…</p>}
      {report?.static_report && (
        <p>
          First pass · {report.static_report.finding_count} scanner findings ·{' '}
          {report.static_report.tools.map(({ tool, status }) => `${tool} ${status}`).join(' · ')}
          {report.static_report.intake_gap_codes.length > 0 && ' · Intake reported coverage gaps'}
        </p>
      )}
      {report?.report && (
        <>
          <p>
            {report.report.model} · {findings.length} model findings ·{' '}
            {report.report.excluded_files} files outside supported source types or paths
          </p>
          {findings.length > 0 && (
            <>
              <p>Verify model findings against the source before confirming them.</p>
              <ul className={styles.findings}>
                {findings.map((finding, index) => (
                  <li key={`${finding.file}:${finding.line}:${index}`}>
                    <div className={styles.findingHeading}>
                      <strong>{finding.title}</strong>
                      <span>{finding.severity}</span>
                    </div>
                    <code>
                      {finding.file}:{finding.line}
                    </code>
                    <pre>{finding.evidence}</pre>
                    <p>{finding.remediation}</p>
                    <p>
                      {finding.related_static_finding_ids.length > 0
                        ? 'Scanner also reported this source location'
                        : 'Additional model finding'}
                    </p>
                  </li>
                ))}
              </ul>
            </>
          )}
          {pending.length > 0 && (
            <details className={styles.details}>
              <summary>Files pending or not fully reviewed ({pending.length})</summary>
              <ul>
                {pending
                  .slice(activePage * pendingPageSize, (activePage + 1) * pendingPageSize)
                  .map(({ file, reason }) => (
                    <li key={file}>
                      <code>{file}</code> · {labelReason(reason)}
                    </li>
                  ))}
              </ul>
              {lastPage > 0 && (
                <div className={styles.controls}>
                  <button
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
                    type="button"
                    disabled={activePage === lastPage}
                    onClick={() => setPage(activePage + 1)}
                  >
                    Next
                  </button>
                </div>
              )}
            </details>
          )}
          {report.report.coverage_gaps.length > 0 && (
            <details className={styles.details}>
              <summary>Model coverage notes ({report.report.coverage_gaps.length})</summary>
              <ul>
                {report.report.coverage_gaps.map((gap, index) => (
                  <li key={index}>{gap}</li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </details>
  );
}
