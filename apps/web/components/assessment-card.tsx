'use client';

import { useState, type SyntheticEvent } from 'react';
import { API_URL } from '@/lib/api';
import type { Assessment } from '@/lib/types';
import { SeverityPill, StatusPill } from './status-pill';
import { DiscoveryPanel } from './discovery-panel';
import { LanguageBreakdown } from './language-breakdown';
import { PassiveCapturePanel } from './passive-capture-panel';
import Link from 'next/link';
import styles from './assessment-card.module.css';

export function AssessmentCard({ assessment }: { assessment: Assessment }) {
  const [detail, setDetail] = useState<Assessment | null>(null);
  const [detailError, setDetailError] = useState('');
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState<'Overview' | 'Findings' | 'Scanner runs' | 'Routes'>('Overview');
  const [severity, setSeverity] = useState('');
  const [scanner, setScanner] = useState('');
  const toolRuns = new Map((detail?.job ?? []).map((run) => [run.id, run]));
  const technologies = assessment.technologies ?? [];
  const detectedLanguages = technologies
    .filter(({ category }) => category === 'language')
    .map(({ name }) => name);
  const tools = technologies.filter(({ category }) => category !== 'language');
  const aiStatus = assessment.ai_review?.status;
  let status: typeof assessment.status | 'incomplete' = assessment.status;
  if (
    aiStatus &&
    assessment.status !== 'cancelled' &&
    assessment.status !== 'queued' &&
    assessment.status !== 'running'
  ) {
    if (aiStatus === 'waiting_for_scans' || aiStatus === 'queued' || aiStatus === 'running')
      status = 'running';
    else if (aiStatus === 'cancelled') status = 'cancelled';
    else if (aiStatus === 'incomplete' || assessment.status === 'failed') status = 'incomplete';
  }

  async function loadAssessmentDetails(event: SyntheticEvent<HTMLDetailsElement>) {
    if (!event.currentTarget.open || detail || loading) return;
    setLoading(true);
    setDetailError('');
    try {
      const response = await fetch(`${API_URL}/assessments/${assessment.id}`, {
        cache: 'no-store',
      });
      if (!response.ok) throw new Error(`Could not load scanner details (${response.status})`);
      setDetail((await response.json()) as Assessment);
    } catch (error) {
      setDetailError(error instanceof Error ? error.message : 'Could not load scanner details');
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <article className={styles.card}>
        <header className={styles.cardHeading}>
          <h2>Assessment overview</h2>
          <StatusPill status={status} prominent />
        </header>
        <p>
          {assessment.source_type === 'zip' ? 'ZIP upload' : 'Mounted repository'} ·{' '}
          {assessment.target_url || `Assessment coverage is ${assessment.coverage_status}`}
        </p>
        <div className={styles.tabs} role="group" aria-label="Assessment views">
          {(['Overview', 'Findings', 'Scanner runs', 'Routes'] as const).map((item) => (
            <button
              type="button"
              key={item}
              aria-pressed={view === item}
              onClick={() => setView(item)}
            >
              {item}
            </button>
          ))}
        </div>
        <section hidden={view !== 'Overview'}>
          <h3>Source inventory</h3>
          <div className={styles.meta}>
            <span>Assessment</span>
            <code>{assessment.id.slice(0, 8)}</code>
            <span className={styles.dot}>·</span>
            <time dateTime={assessment.created_at}>
              {new Date(assessment.created_at).toLocaleString()}
            </time>
          </div>
          <div className={styles.meta}>
            <StatusPill status={assessment.intake_status} prefix="Intake" />
            <StatusPill status={assessment.coverage_status} prefix="Coverage" />
            <span>{assessment.route_count ?? 0} routes</span>
            {assessment.source_identity && (
              <code title={`${assessment.source_identity_type}: ${assessment.source_identity}`}>
                {assessment.source_identity_type === 'git_commit' ? 'commit' : 'sha256'}{' '}
                {assessment.source_identity.slice(0, 12)}
              </code>
            )}
          </div>
          <LanguageBreakdown languages={assessment.source_languages} detected={detectedLanguages} />
          {tools.length > 0 && (
            <section className={styles.technologySection} aria-label="Tools and frameworks">
              <h4>Tools and frameworks</h4>
              <div className={styles.technologies}>
                {tools.map((technology) => (
                  <span key={`${technology.category}-${technology.name}`}>{technology.name}</span>
                ))}
              </div>
            </section>
          )}
          {(assessment.normalized_finding_count ?? 0) > 0 && (
            <div className={styles.severityCounts}>
              {Object.entries(assessment.severity_counts ?? {})
                .filter(([, count]) => Number(count) > 0)
                .map(([severity, count]) => (
                  <SeverityPill level={severity} count={Number(count)} key={severity} />
                ))}
            </div>
          )}
          {!!assessment.findings?.length && (
            <details className={styles.findings}>
              <summary>
                {assessment.findings.length} intake note
                {assessment.findings.length === 1 ? '' : 's'}
              </summary>
              <ul>
                {assessment.findings.map((finding, index) => (
                  <li
                    className={finding.severity === 'error' ? styles.errorFinding : undefined}
                    key={`${finding.code}-${index}`}
                  >
                    {finding.message}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </section>
        <section hidden={view !== 'Routes'}>
          {assessment.routes?.length ? (
            <details className={styles.routes}>
              <summary>
                Review routes ({assessment.route_count ?? assessment.routes.length})
              </summary>
              <ul>
                {assessment.routes.map((route, index) => (
                  <li key={`${route.source_file}:${route.source_line}:${index}`}>
                    <code>
                      {route.method} {route.path}
                    </code>
                    <small>
                      {route.source_file}
                      {route.source_line ? `:${route.source_line}` : ''}
                    </small>
                  </li>
                ))}
              </ul>
            </details>
          ) : (
            <p>No routes recorded.</p>
          )}
          {view === 'Routes' && (
            <>
              <DiscoveryPanel assessmentId={assessment.id} />
              <PassiveCapturePanel assessmentId={assessment.id} />
            </>
          )}
        </section>
      </article>
      <section className={styles.card}>
        <h2>
          {view === 'Scanner runs' || view === 'Findings'
            ? 'Coverage and scanner runs'
            : 'Coverage'}
        </h2>
        <p>Review scanner results and coverage limits before drawing conclusions.</p>
        {view === 'Scanner runs' && (
          <details open className={styles.staticFindings} onToggle={loadAssessmentDetails}>
            <summary>Review scanner runs</summary>
            {loading && <p>Loading scanner details…</p>}
            {detailError && (
              <p className={styles.errorFinding} role="alert">
                {detailError}
              </p>
            )}
            {detail &&
              (() => {
                const scannerRuns = (detail.job ?? []).filter(
                  (run) => run.tool === 'semgrep' || run.tool === 'trivy',
                );
                return scannerRuns.length ? (
                  scannerRuns.map((run) => {
                    const artifacts =
                      detail.artifacts?.filter((artifact) => artifact.tool_run_id === run.id) ?? [];
                    const db =
                      run.tool === 'trivy'
                        ? (run.provenance?.trivy_db as Record<string, unknown> | null | undefined)
                        : null;
                    return (
                      <section className={styles.findingGroup} key={run.id}>
                        <div className={styles.groupHead}>
                          <strong>{run.tool}</strong>
                          <StatusPill status={run.status} />
                          <StatusPill status={run.coverage_status} prefix="Coverage" />
                        </div>
                        <div className={styles.findingMeta}>
                          <span>Tool {run.tool_version ?? 'unknown'}</span>
                          <span>Adapter {run.adapter_version ?? 'unknown'}</span>
                          {run.status === 'completed' && (
                            <span>Exit {run.exit_code ?? 'not run'}</span>
                          )}
                        </div>
                        {run.status === 'failed' && (
                          <p>
                            {run.tool === 'trivy'
                              ? 'Dependency scan could not finish. Any saved findings are available below.'
                              : 'Static scan could not finish. Any saved findings are available below.'}
                          </p>
                        )}
                        <p className={styles.rule}>
                          Config: {run.config_id ?? 'unknown'} · SHA-256{' '}
                          {run.config_sha256 ?? 'unavailable'}
                        </p>
                        {db && (
                          <p className={styles.rule}>
                            Trivy DB v{String(db.version ?? 'unknown')} · metadata SHA-256{' '}
                            {String(db.metadata_sha256 ?? 'unavailable')} · updated{' '}
                            {String(db.updated_at ?? 'unknown')}
                          </p>
                        )}
                        {run.status === 'completed' &&
                          artifacts.map((artifact) => (
                            <a
                              key={artifact.id}
                              href={`${API_URL}/artifacts/${artifact.id}`}
                              target="_blank"
                              rel="noreferrer"
                            >
                              Open {artifact.artifact_kind} ({artifact.byte_size} bytes, SHA-256{' '}
                              {artifact.sha256.slice(0, 12)})
                            </a>
                          ))}
                      </section>
                    );
                  })
                ) : (
                  <p>No static scanner runs recorded.</p>
                );
              })()}
          </details>
        )}
        {assessment.ai_review && (
          <Link href={`/ai-review?assessment=${encodeURIComponent(assessment.id)}`}>
            Open AI Code Review
          </Link>
        )}
      </section>
      {view === 'Findings' && (
        <section className={styles.card}>
          <h2>Static findings</h2>
          <div className={styles.tabs}>
            <select
              aria-label="Severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="">All severities</option>
              {['critical', 'high', 'medium', 'low', 'info', 'unknown'].map((level) => (
                <option key={level}>{level}</option>
              ))}
            </select>
            <select
              aria-label="Scanner"
              value={scanner}
              onChange={(event) => setScanner(event.target.value)}
            >
              <option value="">All scanners</option>
              {[...new Set((detail?.job ?? []).map(({ tool }) => tool))].map((tool) => (
                <option key={tool}>{tool}</option>
              ))}
            </select>
          </div>
          <details open className={styles.staticFindings} onToggle={loadAssessmentDetails}>
            <summary>Review static findings ({assessment.normalized_finding_count ?? 0})</summary>
            {loading && <p>Loading findings…</p>}
            {detailError && (
              <p className={styles.errorFinding} role="alert">
                {detailError}
              </p>
            )}
            {detail?.finding_groups
              ?.filter(
                (group) =>
                  (!severity || group.severity === severity) &&
                  (!scanner ||
                    group.findings.some(
                      (item) => toolRuns.get(item.tool_run_id)?.tool === scanner,
                    )),
              )
              .map((group) => (
                <section className={styles.findingGroup} key={group.id}>
                  <div className={styles.groupHead}>
                    <SeverityPill level={group.severity} />
                    <strong>{group.title}</strong>
                    {group.duplicate_count > 1 && (
                      <small>{group.duplicate_count} grouped copies</small>
                    )}
                  </div>
                  {group.findings
                    .filter((item) => !scanner || toolRuns.get(item.tool_run_id)?.tool === scanner)
                    .map((finding) => {
                      const run = toolRuns.get(finding.tool_run_id);
                      const artifact = detail.artifacts?.find(
                        (item) => item.id === finding.artifact_id,
                      );
                      const location = finding.source_file
                        ? `${finding.source_file}${finding.start_line ? `:${finding.start_line}${finding.start_column ? `:${finding.start_column}` : ''}` : ''}`
                        : 'Location unavailable';
                      return (
                        <article className={styles.originalFinding} key={finding.id}>
                          <div className={styles.findingMeta}>
                            <span>
                              {run?.tool ?? 'scanner'} {run?.tool_version ?? ''}
                            </span>
                            <span>{finding.finding_type}</span>
                            <span>
                              Confidence:{' '}
                              {finding.confidence == null
                                ? 'not reported'
                                : `${Math.round(finding.confidence * 100)}%`}
                            </span>
                          </div>
                          <code>{location}</code>
                          <p>{finding.message}</p>
                          <p className={styles.rule}>
                            {finding.rule_id ? `Rule: ${finding.rule_id}` : ''}
                            {finding.cve_id ? ` · CVE: ${finding.cve_id}` : ''}
                          </p>
                          <details className={styles.evidence}>
                            <summary>Evidence and provenance</summary>
                            <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
                            <small>
                              Raw result: {finding.raw_pointer} · SHA-256{' '}
                              {artifact?.sha256 ?? 'unavailable'}
                            </small>
                            {artifact && (
                              <a
                                href={`${API_URL}/artifacts/${artifact.id}`}
                                target="_blank"
                                rel="noreferrer"
                              >
                                Open original {artifact.artifact_kind}
                              </a>
                            )}
                          </details>
                        </article>
                      );
                    })}
                </section>
              ))}
          </details>
        </section>
      )}
      <a href={`${API_URL}/assessments/${assessment.id}`} target="_blank" rel="noreferrer">
        View assessment details <span aria-hidden="true">↗</span>
      </a>
    </>
  );
}
