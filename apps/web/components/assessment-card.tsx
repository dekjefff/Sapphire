'use client';

import { useState, type SyntheticEvent } from 'react';
import type { Assessment } from '@/lib/types';
import { StatusPill } from './status-pill';
import styles from './assessment-card.module.css';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export function AssessmentCard({ assessment }: { assessment: Assessment }) {
  const [detail, setDetail] = useState<Assessment | null>(null);
  const [detailError, setDetailError] = useState('');
  const [loading, setLoading] = useState(false);
  const toolRuns = new Map((detail?.job ?? []).map((run) => [run.id, run]));

  async function loadAssessmentDetails(event: SyntheticEvent<HTMLDetailsElement>) {
    if (!event.currentTarget.open || detail || loading) return;
    setLoading(true);
    setDetailError('');
    try {
      const response = await fetch(`${API_URL}/assessments/${assessment.id}`, { cache: 'no-store' });
      if (!response.ok) throw new Error(`Could not load scanner details (${response.status})`);
      setDetail((await response.json()) as Assessment);
    } catch (error) {
      setDetailError(error instanceof Error ? error.message : 'Could not load scanner details');
    } finally {
      setLoading(false);
    }
  }

  return (
    <article className={styles.card}>
      <div className={styles.top}>
        <div className={styles.avatar} aria-hidden="true">
          {assessment.project_name.slice(0, 1).toUpperCase()}
        </div>
        <div className={styles.title}>
          <strong>{assessment.project_name}</strong>
          <small>{assessment.target_url}</small>
        </div>
        <StatusPill status={assessment.status} />
      </div>
      <div className={styles.meta}>
        <span>Assessment</span>
        <code>{assessment.id.slice(0, 8)}</code>
        <span className={styles.dot}>·</span>
        <time dateTime={assessment.created_at}>
          {new Date(assessment.created_at).toLocaleString()}
        </time>
      </div>
      <div className={styles.meta}>
        <span>Intake: {assessment.intake_status}</span>
        <span className={styles.dot}>·</span>
        <span>Coverage: {assessment.coverage_status}</span>
        <span className={styles.dot}>·</span>
        <span>{assessment.route_count ?? 0} routes</span>
        {assessment.source_identity && <code title={`${assessment.source_identity_type}: ${assessment.source_identity}`}>{assessment.source_identity_type === 'git_commit' ? 'commit' : 'sha256'} {assessment.source_identity.slice(0, 12)}</code>}
      </div>
      {!!assessment.technologies?.length && <div className={styles.technologies} aria-label="Detected technologies">{assessment.technologies.map((technology) => <span key={`${technology.category}-${technology.name}`}>{technology.name}</span>)}</div>}
      {(assessment.normalized_finding_count ?? 0) > 0 && <div className={styles.severityCounts}>{Object.entries(assessment.severity_counts ?? {}).filter(([, count]) => Number(count) > 0).map(([severity, count]) => <span className={styles[severity]} key={severity}>{severity}: {count}</span>)}</div>}
      {!!assessment.findings?.length && <details className={styles.findings}><summary>{assessment.findings.length} intake note{assessment.findings.length === 1 ? '' : 's'}</summary><ul>{assessment.findings.map((finding, index) => <li className={finding.severity === 'error' ? styles.errorFinding : undefined} key={`${finding.code}-${index}`}>{finding.message}</li>)}</ul></details>}
      {!!assessment.routes?.length && <details className={styles.routes}><summary>Review routes ({assessment.route_count ?? assessment.routes.length})</summary><ul>{assessment.routes.map((route, index) => <li key={`${route.source_file}:${route.source_line}:${index}`}><code>{route.method} {route.path}</code><small>{route.source_file}{route.source_line ? `:${route.source_line}` : ''}</small></li>)}</ul></details>}
      <details className={styles.staticFindings} onToggle={loadAssessmentDetails}>
        <summary>Review scanner runs</summary>
        {loading && <p>Loading scanner details…</p>}
        {detailError && <p className={styles.errorFinding} role="alert">{detailError}</p>}
        {detail && (() => {
          const scannerRuns = (detail.job ?? []).filter((run) => run.tool === 'semgrep' || run.tool === 'trivy');
          return scannerRuns.length ? scannerRuns.map((run) => {
            const artifacts = detail.artifacts?.filter((artifact) => artifact.tool_run_id === run.id) ?? [];
            const db = run.tool === 'trivy' ? (run.provenance?.trivy_db as Record<string, unknown> | null | undefined) : null;
            return <section className={styles.findingGroup} key={run.id}>
              <div className={styles.groupHead}><strong>{run.tool}</strong><span>{run.status} · coverage {run.coverage_status}</span></div>
              <div className={styles.findingMeta}><span>Tool {run.tool_version ?? 'unknown'}</span><span>Adapter {run.adapter_version ?? 'unknown'}</span><span>Exit {run.exit_code ?? 'not run'}</span></div>
              <p>{run.error ? `Reason: ${run.error}` : 'No scanner error recorded.'}</p>
              <p className={styles.rule}>Config: {run.config_id ?? 'unknown'} · SHA-256 {run.config_sha256 ?? 'unavailable'}</p>
              {db && <p className={styles.rule}>Trivy DB v{String(db.version ?? 'unknown')} · metadata SHA-256 {String(db.metadata_sha256 ?? 'unavailable')} · updated {String(db.updated_at ?? 'unknown')}</p>}
              {artifacts.map((artifact) => <a key={artifact.id} href={`${API_URL}/artifacts/${artifact.id}`} target="_blank" rel="noreferrer">Open {artifact.artifact_kind} ({artifact.byte_size} bytes, SHA-256 {artifact.sha256.slice(0, 12)})</a>)}
            </section>;
          }) : <p>No static scanner runs recorded.</p>;
        })()}
      </details>
      {(assessment.normalized_finding_count ?? 0) > 0 && <details className={styles.staticFindings} onToggle={loadAssessmentDetails}><summary>Review static findings ({assessment.normalized_finding_count})</summary>{loading && <p>Loading findings…</p>}{detailError && <p className={styles.errorFinding} role="alert">{detailError}</p>}{detail?.finding_groups?.map((group) => <section className={styles.findingGroup} key={group.id}><div className={styles.groupHead}><span className={`${styles.severity} ${styles[group.severity]}`}>{group.severity}</span><strong>{group.title}</strong>{group.duplicate_count > 1 && <small>{group.duplicate_count} grouped copies</small>}</div>{group.findings.map((finding) => { const run = toolRuns.get(finding.tool_run_id); const artifact = detail.artifacts?.find((item) => item.id === finding.artifact_id); const location = finding.source_file ? `${finding.source_file}${finding.start_line ? `:${finding.start_line}${finding.start_column ? `:${finding.start_column}` : ''}` : ''}` : 'Location unavailable'; return <article className={styles.originalFinding} key={finding.id}><div className={styles.findingMeta}><span>{run?.tool ?? 'scanner'} {run?.tool_version ?? ''}</span><span>{finding.finding_type}</span><span>Confidence: {finding.confidence == null ? 'not reported' : `${Math.round(finding.confidence * 100)}%`}</span></div><code>{location}</code><p>{finding.message}</p><p className={styles.rule}>{finding.rule_id ? `Rule: ${finding.rule_id}` : ''}{finding.cve_id ? ` · CVE: ${finding.cve_id}` : ''}</p><details className={styles.evidence}><summary>Evidence and provenance</summary><pre>{JSON.stringify(finding.evidence, null, 2)}</pre><small>Raw result: {finding.raw_pointer} · SHA-256 {artifact?.sha256 ?? 'unavailable'}</small>{artifact && <a href={`${API_URL}/artifacts/${artifact.id}`} target="_blank" rel="noreferrer">Open original {artifact.artifact_kind}</a>}</details></article>; })}</section>)}</details>}
      <a href={`${API_URL}/assessments/${assessment.id}`} target="_blank" rel="noreferrer">
        View assessment details <span aria-hidden="true">↗</span>
      </a>
    </article>
  );
}
