'use client';

import { useState } from 'react';
import styles from './review-workspace.module.css';

type Finding = {
  title: string;
  severity: string;
  file: string;
  line: number;
  evidence: string;
  remediation: string;
  related_static_finding_ids?: string[];
};

const levels = ['critical', 'high', 'medium', 'low', 'info'];

export function ReviewFindings({ findings }: { findings: readonly Finding[] }) {
  const [filter, setFilter] = useState('all');
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

  return (
    <>
      <div className={styles.filters} role="group" aria-label="Filter findings by severity">
        {['all', ...options].map((level) => (
          <button
            key={level}
            type="button"
            aria-pressed={level === filter}
            onClick={() => setFilter(level)}
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
          ? `${visible.length} findings shown`
          : filter === 'all'
            ? 'No model findings reported.'
            : 'No findings at this severity.'}
      </p>
      {visible.map((finding, index) => (
        <details
          className={styles.finding}
          key={`${finding.file}:${finding.line}:${index}:${filter}`}
        >
          <summary>
            <span className={styles.severity} data-level={finding.severity.toLowerCase()}>
              {finding.severity}
            </span>
            <span>
              <strong>{finding.title}</strong>
              <code>
                {finding.file}:{finding.line}
              </code>
            </span>
          </summary>
          <div className={styles.evidence}>
            <pre>{finding.evidence}</pre>
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
    </>
  );
}
