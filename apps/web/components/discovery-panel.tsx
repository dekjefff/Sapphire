'use client';

import { useState, type SyntheticEvent } from 'react';
import { API_URL, fetchAssessmentDetail } from '@/lib/api';
import type { Assessment, DiscoveryMatch } from '@/lib/types';
import styles from './assessment-card.module.css';
import { StatusPill } from './status-pill';

const REASONS: Record<string, string> = {
  route_matched: 'Runtime endpoint matched an identified source route.',
  source_only_not_observed: 'Source route was not observed during the bounded crawl.',
  no_source_route_match: 'Runtime endpoint did not match an identified source route.',
  unresolved_route: 'Runtime endpoint matched multiple source route candidates.',
  generated_content_skipped: 'Known generated or dependency content was skipped.',
  intake_link_skipped: 'A filesystem or archive link was skipped safely.',
  scope_limited: 'The approved scope limited discovery coverage.',
  policy_limited: 'The approved scope limited discovery coverage.',
  redirect_denied: 'A redirect was observed and not followed.',
  crawl_depth_exhausted: 'The crawl reached its depth limit.',
  url_budget_exhausted: 'The crawl reached its URL limit.',
  byte_budget_exhausted: 'The crawl reached its response byte limit.',
  rate_budget_exhausted: 'The crawl reached its request rate limit.',
  concurrency_budget_exhausted: 'The crawl reached its concurrency limit.',
  timeout: 'Discovery exceeded its time limit.',
  cancelled: 'Discovery was cancelled.',
  tool_failed: 'A discovery tool did not complete successfully.',
  malformed_tool_output: 'A discovery tool returned invalid output.',
  parser_limitation: 'The discovery parser could not fully interpret the result.',
  dns_policy_rejected: 'The resolved destination did not satisfy network policy.',
  peer_ip_mismatch: 'The connected peer did not match the approved address set.',
};
const TABS = ['matched', 'source_only', 'runtime_only', 'unresolved'] as const;

function timestamp(value?: string | null) {
  return value ? new Date(value).toLocaleString() : 'not recorded';
}

function Provenance({ row }: { row: DiscoveryMatch }) {
  const artifactId = row.evidence?.artifact_id;
  return (
    <div className={styles.discoveryProvenance}>
      {row.source_file && (
        <span>
          Source:{' '}
          <code>
            {row.source_file}
            {row.source_line ? `:${row.source_line}` : ''}
          </code>
        </span>
      )}
      {row.evidence?.source_route_id && (
        <span>
          Source evidence ID: <code>{row.evidence.source_route_id}</code>
        </span>
      )}
      {row.evidence?.tool_run_id && (
        <span>
          Run: <code>{row.evidence.tool_run_id.slice(0, 8)}</code>
        </span>
      )}
      {row.evidence?.scope_policy_sha256 && (
        <span>
          Scope SHA-256: <code>{row.evidence.scope_policy_sha256.slice(0, 12)}</code>
        </span>
      )}
      {row.evidence?.raw_pointer && (
        <span>
          Raw pointer: <code>{row.evidence.raw_pointer}</code>
        </span>
      )}
      {artifactId && (
        <a
          href={`${API_URL}/artifacts/${encodeURIComponent(artifactId)}`}
          target="_blank"
          rel="noreferrer"
        >
          Open raw artifact
        </a>
      )}
    </div>
  );
}

export function DiscoveryPanel({ assessmentId }: { assessmentId: string }) {
  const [detail, setDetail] = useState<Assessment | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<(typeof TABS)[number]>('matched');
  const [limit, setLimit] = useState(50);
  const [endpointCursor, setEndpointCursor] = useState(0);
  const [matchCursor, setMatchCursor] = useState(0);

  async function load(
    event?: SyntheticEvent<HTMLDetailsElement>,
    next: { limit?: number; endpointCursor?: number; matchCursor?: number } = {},
  ) {
    if (event && !event.currentTarget.open) return;
    setLoading(true);
    setError('');
    try {
      const page = { limit, endpointCursor, matchCursor, ...next };
      const response = await fetchAssessmentDetail(assessmentId, page);
      setDetail(response);
      if (next.limit !== undefined) setLimit(next.limit);
      if (next.endpointCursor !== undefined) setEndpointCursor(next.endpointCursor);
      if (next.matchCursor !== undefined) setMatchCursor(next.matchCursor);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load discovery details');
    } finally {
      setLoading(false);
    }
  }

  const discovery = detail?.discovery;
  const runs = (detail?.job ?? []).filter((run) => run.tool === 'httpx' || run.tool === 'katana');
  const visibleMatches = (discovery?.matches.items ?? []).filter(
    (row) => row.coverage_class === tab,
  );
  const budget = discovery?.budget ?? {
    profile_id: 'discovery-default-v1',
    crawl_depth: 3,
    unique_urls: 500,
    global_concurrency: 2,
    per_host_concurrency: 1,
    requests_per_second: 2,
    per_host_requests_per_second: 1,
    connect_timeout_seconds: 5,
    request_timeout_seconds: 10,
    retries: 0,
    max_response_bytes: 1_048_576,
    total_response_bytes: 52_428_800,
    wall_clock_seconds: 120,
  };
  const stateLabels: Record<string, string> = {
    not_authorized: 'Not authorized · no runtime requests queued',
    pending: 'Authorized · waiting to run',
    running: 'Running',
    complete: 'Complete',
    incomplete: 'Incomplete coverage',
    failed: 'Failed · incomplete coverage',
    cancelled: 'Cancelled · incomplete coverage',
    empty: 'No endpoints found',
  };

  return (
    <details className={styles.discoverySection} onToggle={(event) => void load(event)}>
      <summary>Review runtime discovery</summary>
      {loading && <p>Loading discovery details…</p>}
      {error && (
        <p className={styles.errorFinding} role="alert">
          {error}
        </p>
      )}
      {discovery && (
        <>
          <div className={styles.discoveryState}>
            <StatusPill
              status={discovery.state}
              label={stateLabels[discovery.state] ?? 'Discovery state unavailable'}
            />
            <span>
              {discovery.endpoint_count} endpoints · {discovery.match_count} route comparisons
            </span>
          </div>
          {discovery.scope ? (
            <section className={styles.findingGroup}>
              <div className={styles.groupHead}>
                <strong>Authorized scope</strong>
                <span>
                  Local test profile:{' '}
                  {discovery.scope.policy_revision === 'juiceshop-local-v1'
                    ? 'yes · Juice Shop'
                    : 'operator profile'}
                </span>
              </div>
              <p>
                <code>
                  {discovery.scope.scheme}://{discovery.scope.host}:{discovery.scope.port}
                </code>{' '}
                ·{' '}
                {discovery.scope.path_mode === 'whole_origin'
                  ? 'whole origin'
                  : `path prefixes: ${discovery.scope.path_prefixes.join(', ')}`}
              </p>
              <p className={styles.rule}>
                Policy {discovery.scope.policy_revision} · scope SHA-256{' '}
                {discovery.scope.policy_sha256.slice(0, 12)} · authorized{' '}
                {timestamp(discovery.scope.authorized_at)} · expires{' '}
                {timestamp(discovery.scope.expires_at)}
              </p>
              <p className={styles.rule}>
                Budget {budget.profile_id}: GET only · depth {budget.crawl_depth} · up to{' '}
                {budget.unique_urls} URLs · concurrency {budget.global_concurrency} global /{' '}
                {budget.per_host_concurrency} per host · {budget.per_host_requests_per_second}{' '}
                request/second per host · connect {budget.connect_timeout_seconds}s / request{' '}
                {budget.request_timeout_seconds}s · {budget.retries} retries ·{' '}
                {Math.round(budget.max_response_bytes / 1_048_576)} MiB/response ·{' '}
                {Math.round(budget.total_response_bytes / 1_048_576)} MiB total ·{' '}
                {budget.wall_clock_seconds}s wall time
              </p>
            </section>
          ) : (
            <p>
              No runtime discovery authorization was recorded. Source intake and static scanning may
              still run.
            </p>
          )}
          <div className={styles.discoveryCounts} aria-label="Coverage counts">
            {TABS.map((key) => (
              <span key={key}>
                <strong>{discovery.counts[key]}</strong> {key.replace('_', ' ')}
              </span>
            ))}
          </div>
          {Object.entries(discovery.reason_counts).length > 0 && (
            <section className={styles.findingGroup}>
              <strong>Coverage reasons</strong>
              <ul className={styles.reasonList}>
                {Object.entries(discovery.reason_counts).map(([code, count]) => (
                  <li key={code}>
                    <code>{code}</code> ·{' '}
                    {REASONS[code] ?? 'Coverage was limited by this recorded reason.'} ({count})
                  </li>
                ))}
              </ul>
            </section>
          )}
          <section className={styles.findingGroup}>
            <div className={styles.groupHead}>
              <strong>Discovery runs</strong>
            </div>
            {runs.length ? (
              runs.map((run) => (
                <article className={styles.discoveryRun} key={run.id}>
                  <div className={styles.groupHead}>
                    <strong>{run.tool}</strong>
                    <StatusPill status={run.status} />
                    <StatusPill status={run.coverage_status} prefix="Coverage" />
                  </div>
                  <div className={styles.findingMeta}>
                    <span>Tool {run.tool_version ?? 'unknown'}</span>
                    <span>Adapter {run.adapter_version ?? 'unknown'}</span>
                    <span>Started {timestamp(run.started_at)}</span>
                    <span>Finished {timestamp(run.finished_at)}</span>
                  </div>
                  <p className={styles.rule}>
                    Reason: {run.failure_reason_code ?? 'none'} · Config{' '}
                    {run.config_id ?? 'unknown'} · config SHA-256{' '}
                    {run.config_sha256?.slice(0, 12) ?? 'unavailable'}
                  </p>
                  {run.counters && (
                    <p className={styles.rule}>
                      Requests {run.counters.requests_sent ?? 0} · responses{' '}
                      {run.counters.responses_received ?? 0} · bytes{' '}
                      {run.counters.response_bytes ?? 0} · policy denials{' '}
                      {run.counters.policy_denials ?? 0} · redirects denied{' '}
                      {run.counters.redirects_denied ?? 0}
                    </p>
                  )}
                </article>
              ))
            ) : (
              <p>
                No discovery runs recorded. Failed or cancelled runs remain visible here when
                recorded by the API.
              </p>
            )}
          </section>
          <section className={styles.findingGroup}>
            <div className={styles.groupHead}>
              <strong>Route comparison</strong>
              <label className={styles.pageSize}>
                Rows
                <select
                  value={limit}
                  onChange={(event) =>
                    void load(undefined, {
                      limit: Number(event.target.value),
                      endpointCursor: 0,
                      matchCursor: 0,
                    })
                  }
                >
                  <option>10</option>
                  <option>25</option>
                  <option>50</option>
                  <option>100</option>
                </select>
              </label>
            </div>
            <div className={styles.discoveryTabs} role="tablist" aria-label="Coverage class">
              {TABS.map((key) => (
                <button
                  type="button"
                  role="tab"
                  aria-selected={tab === key}
                  className={tab === key ? styles.activeTab : ''}
                  key={key}
                  onClick={() => setTab(key)}
                >
                  {key.replace('_', ' ')} ({discovery.counts[key]})
                </button>
              ))}
            </div>
            {visibleMatches.length ? (
              visibleMatches.map((row) => {
                const endpoint = discovery.endpoints.items.find(
                  (item) => item.id === row.runtime_endpoint_id,
                );
                const endpointPath = endpoint
                  ? `${endpoint.method} ${endpoint.scheme}://${endpoint.host}:${endpoint.port}${endpoint.path}`
                  : null;
                return (
                  <article className={styles.discoveryRow} key={row.id}>
                    <div className={styles.groupHead}>
                      <strong>{row.coverage_class.replace('_', ' ')}</strong>
                      <code>{row.reason_code}</code>
                    </div>
                    {endpointPath && (
                      <p>
                        <code>{endpointPath}</code>
                        {endpoint?.status_code !== null && endpoint?.status_code !== undefined
                          ? ` · HTTP ${endpoint.status_code}`
                          : ' · status unavailable'}
                      </p>
                    )}
                    {row.source_route && (
                      <p>
                        Source:{' '}
                        <code>
                          {row.source_method} {row.source_route}
                        </code>
                      </p>
                    )}
                    {row.coverage_class === 'unresolved' && (
                      <p>
                        {row.candidate_source_route_ids.length} possible source route candidates
                      </p>
                    )}
                    <p className={styles.rule}>
                      {REASONS[row.reason_code] ?? 'Recorded coverage reason.'}
                    </p>
                    <Provenance row={row} />
                  </article>
                );
              })
            ) : (
              <p>
                No {tab.replace('_', ' ')} rows on this page
                {discovery.match_count === 0 ? ' — no route comparisons were recorded.' : '.'}
              </p>
            )}
            <div className={styles.pagination}>
              <button
                type="button"
                disabled={loading || matchCursor === 0}
                onClick={() =>
                  void load(undefined, { matchCursor: Math.max(0, matchCursor - limit) })
                }
              >
                Previous
              </button>
              <span>
                Matches {Math.min(matchCursor + 1, discovery.match_count)}–
                {Math.min(matchCursor + discovery.matches.items.length, discovery.match_count)} of{' '}
                {discovery.match_count}
              </span>
              <button
                type="button"
                disabled={loading || discovery.matches.next_cursor === null}
                onClick={() =>
                  void load(undefined, {
                    matchCursor: discovery.matches.next_cursor ?? matchCursor,
                  })
                }
              >
                Next
              </button>
            </div>
          </section>
          <section className={styles.findingGroup}>
            <strong>Observed endpoints ({discovery.endpoint_count})</strong>
            {discovery.endpoints.items.length ? (
              discovery.endpoints.items.map((endpoint) => (
                <article className={styles.discoveryRow} key={endpoint.id}>
                  <p>
                    <code>
                      {endpoint.method} {endpoint.scheme}://{endpoint.host}:{endpoint.port}
                      {endpoint.path}
                    </code>
                    {endpoint.status_code !== null
                      ? ` · HTTP ${endpoint.status_code}`
                      : ' · status unavailable'}
                  </p>
                  <p className={styles.rule}>
                    Content type {endpoint.content_type ?? 'unknown'} · length{' '}
                    {endpoint.content_length ?? 'unknown'} · seen{' '}
                    {timestamp(endpoint.first_seen_at)}
                  </p>
                  <Provenance
                    row={{
                      id: endpoint.id,
                      runtime_endpoint_id: endpoint.id,
                      coverage_class: 'runtime_only',
                      source_method: null,
                      source_route: null,
                      source_file: null,
                      source_line: null,
                      candidate_source_route_ids: [],
                      reason_code: 'no_source_route_match',
                      evidence: {
                        artifact_id: endpoint.artifact_id,
                        tool_run_id: endpoint.tool_run_id,
                        scope_policy_sha256: endpoint.scope_policy_sha256,
                        raw_pointer: null,
                      },
                    }}
                  />
                </article>
              ))
            ) : (
              <p>No endpoints were persisted. Check run status and failure reasons above.</p>
            )}
            <div className={styles.pagination}>
              <button
                type="button"
                disabled={loading || endpointCursor === 0}
                onClick={() =>
                  void load(undefined, { endpointCursor: Math.max(0, endpointCursor - limit) })
                }
              >
                Previous endpoints
              </button>
              <span>
                Endpoints {Math.min(endpointCursor + 1, discovery.endpoint_count)}–
                {Math.min(
                  endpointCursor + discovery.endpoints.items.length,
                  discovery.endpoint_count,
                )}{' '}
                of {discovery.endpoint_count}
              </span>
              <button
                type="button"
                disabled={loading || discovery.endpoints.next_cursor === null}
                onClick={() =>
                  void load(undefined, {
                    endpointCursor: discovery.endpoints.next_cursor ?? endpointCursor,
                  })
                }
              >
                Next endpoints
              </button>
            </div>
          </section>
        </>
      )}
    </details>
  );
}
