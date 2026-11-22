'use client';

import { useState } from 'react';
import type { SourceEvidenceContext } from '@/lib/types';
import { ReviewCodeBlock } from './review-code-block';
import { SeverityPill } from './status-pill';
import styles from './review-workspace.module.css';

type Finding = {
  title: string;
  severity: string;
  file: string;
  line: number;
  evidence: string;
  evidence_context?: SourceEvidenceContext;
  remediation: string;
  related_static_finding_ids?: string[];
};

const findingsPerPage = 10;
const levels = ['critical', 'high', 'medium', 'low', 'info'];

export function ReviewFindings({ findings }: { findings: readonly Finding[] }) {
  const [filter, setFilter] = useState('all');
  const [page, setPage] = useState(0);
  const counts = new Map<string, number>();
  for (const { severity } of findings) {
    const level = severity.toLowerCase();
    counts.set(level, (counts.get(level) ?? 0) + 1);
  }
  const options = [...new Set([...levels, ...counts.keys()])];
  const visible =
    filter === 'all'
      ? findings
      : findings.filter(({ severity }) => severity.toLowerCase() === filter);

  const pageCount = Math.ceil(visible.length / findingsPerPage);
  const currentPage = Math.min(page, Math.max(pageCount - 1, 0));
  const start = currentPage * findingsPerPage;
  const end = Math.min(start + findingsPerPage, visible.length);

  return (
    <>
      <div className={styles.filters} role="group" aria-label="Filter findings by severity">
        {['all', ...options].map((level) => (
          <button
            key={level}
            type="button"
            aria-pressed={level === filter}
            onClick={() => {
              setFilter(level);
              setPage(0);
            }}
          >
            {level} <span>{level === 'all' ? findings.length : (counts.get(level) ?? 0)}</span>
          </button>
        ))}
      </div>
      {findings.length > 0 && (
        <p className={styles.muted}>Verify model findings against the source.</p>
      )}
      <p className={styles.muted} role="status">
        {visible.length
          ? `Showing ${start + 1}–${end} of ${visible.length} findings`
          : filter === 'all'
            ? 'No model findings reported.'
            : 'No findings at this severity.'}
      </p>
      {visible.slice(start, end).map((finding, index) => (
        <details
          className={styles.finding}
          key={`${finding.file}:${finding.line}:${start + index}:${filter}`}
        >
          <summary>
            <SeverityPill level={finding.severity.toLowerCase()} />
            <span>
              <strong>{finding.title}</strong>
              <code>
                {finding.file}:{finding.line}
              </code>
            </span>
          </summary>
          <div className={styles.evidence}>
            {finding.evidence && (
              <ReviewCodeBlock
                file={finding.file}
                firstLine={finding.evidence_context?.first_line ?? finding.line}
                citedLine={finding.line}
                evidence={finding.evidence_context?.lines.join('\n') ?? finding.evidence}
              />
            )}
            {finding.evidence && !finding.evidence_context && !/[\r\n]/.test(finding.evidence) && (
              <p className={styles.muted}>Only the cited line was saved for this finding.</p>
            )}
            <p>{finding.remediation}</p>
            {finding.related_static_finding_ids && (
              <p>
                {finding.related_static_finding_ids.length > 0
                  ? 'Scanner also reported this source location'
                  : 'Additional model finding'}
              </p>
            )}
          </div>
        </details>
      ))}
      {pageCount > 1 && (
        <nav className={styles.pagination} aria-label="Finding pages">
          <button
            type="button"
            className={styles.control}
            disabled={currentPage === 0}
            onClick={() => setPage(currentPage - 1)}
          >
            Previous
          </button>
          <span>
            Page {currentPage + 1} of {pageCount}
          </span>
          <button
            type="button"
            className={styles.control}
            disabled={currentPage === pageCount - 1}
            onClick={() => setPage(currentPage + 1)}
          >
            Next
          </button>
        </nav>
      )}
    </>
  );
}
