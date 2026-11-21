'use client';

import { useId, useState, type FormEvent, type SyntheticEvent } from 'react';
import { fetchLatestPassiveCapture, importPassiveCapture } from '@/lib/api';
import type { PassiveCapture, PassiveCaptureItem } from '@/lib/types';
import styles from './passive-capture-panel.module.css';
import { StatusPill } from './status-pill';

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const ITEM_REASONS = {
  not_reached: 'Not reached',
  error: 'Collection error',
  not_applicable: 'Not applicable',
};
const RUN_ERRORS = {
  session_check_failed: 'Session check failed',
  collection_failed: 'Collection failed',
};

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

async function readBundle(file: File): Promise<string> {
  if (file.size > MAX_FILE_BYTES) throw new Error('Choose a capture bundle no larger than 10 MiB.');
  let bundle: unknown;
  try {
    bundle = JSON.parse(await file.text());
  } catch {
    throw new Error('Choose a valid JSON capture bundle.');
  }
  if (
    !object(bundle) ||
    !object(bundle.manifest) ||
    typeof bundle.signature !== 'string' ||
    !/^[a-f0-9]{64}$/.test(bundle.signature) ||
    !object(bundle.har) ||
    !object(bundle.har.log) ||
    !Array.isArray(bundle.har.log.entries)
  ) {
    throw new Error('Choose a signed capture bundle with HAR, manifest, and signature.');
  }
  const entries = bundle.har.log.entries.map((entry: unknown) => {
    if (
      !object(entry) ||
      !object(entry.request) ||
      !object(entry.response) ||
      typeof entry.request.method !== 'string' ||
      !/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(entry.request.method) ||
      typeof entry.response.status !== 'number' ||
      typeof entry.startedDateTime !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(
        entry.startedDateTime,
      ) ||
      typeof entry._sapphire_route_tag !== 'string' ||
      !/^[a-f0-9]{64}$/.test(entry._sapphire_route_tag)
    ) {
      throw new Error('Use the redacted HAR from the signed capture export.');
    }
    return {
      startedDateTime: entry.startedDateTime,
      request: { method: entry.request.method },
      response: { status: entry.response.status },
      _sapphire_route_tag: entry._sapphire_route_tag,
    };
  });
  return JSON.stringify({
    har: { log: { version: '1.2', entries } },
    manifest: bundle.manifest,
    signature: bundle.signature,
  });
}

function CaptureItems({ heading, items }: { heading: string; items: PassiveCaptureItem[] }) {
  if (!items.length) return null;
  return (
    <details className={styles.subsection}>
      <summary>
        {heading} ({items.length})
      </summary>
      <ul>
        {items.map((item) => (
          <li key={item.id}>
            <span>{item.label ?? item.id}</span> · {item.status}
            {item.reason && ` · ${ITEM_REASONS[item.reason]}`}
          </li>
        ))}
      </ul>
    </details>
  );
}

function CaptureResult({ capture }: { capture: PassiveCapture }) {
  const { session, counts } = capture;
  const milestones = capture.manifest?.events.filter(
    (event, index, events) =>
      index === 0 || event.status !== events[index - 1]?.status || event.error,
  );
  return (
    <section className={styles.result} aria-label="Latest passive capture">
      <h3>Latest passive capture</h3>
      <dl>
        <dt>Run ID</dt>
        <dd>
          <code>{capture.run_id}</code>
        </dd>
        <dt>Authentication</dt>
        <dd>
          {capture.authentication}
          {(session?.state ?? capture.asserted_session) &&
            ` · ${session?.state ?? capture.asserted_session}`}
          {session?.role && ` · ${session.role}`}
        </dd>
        {session && (
          <>
            <dt>Session check</dt>
            <dd>
              {session.method.replaceAll('_', ' ')} ·{' '}
              <time dateTime={session.checked_at}>
                {new Date(session.checked_at).toLocaleString()}
              </time>
              {session.first_request !== null &&
                ` · requests ${session.first_request}–${session.last_request}`}
            </dd>
          </>
        )}
        <dt>Coverage</dt>
        <dd>
          {capture.coverage}
          {counts && ` · ${counts.observed} of ${counts.expected} observed`}
        </dd>
        {counts && (
          <>
            <dt>Run progress</dt>
            <dd>
              {capture.manifest?.status} · {counts.processed} processed · {counts.remaining}{' '}
              remaining · {counts.requests} requests
            </dd>
          </>
        )}
      </dl>
      <CaptureItems heading="Observed items" items={capture.observed ?? []} />
      <CaptureItems heading="Coverage gaps" items={capture.gaps ?? []} />
      {!!milestones?.length && (
        <details className={styles.subsection}>
          <summary>Run timeline</summary>
          <ol>
            {milestones.map((event, index) => (
              <li key={`${event.at}-${index}`}>
                <time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time>
                {' · '}
                <StatusPill status={event.status} />
                {event.error && ` · ${RUN_ERRORS[event.error]}`}
              </li>
            ))}
          </ol>
        </details>
      )}
    </section>
  );
}

export function PassiveCapturePanel({ assessmentId }: { assessmentId: string }) {
  const inputId = useId();
  const [capture, setCapture] = useState<PassiveCapture | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState('');
  const [notice, setNotice] = useState('');

  async function loadLatest(event: SyntheticEvent<HTMLDetailsElement>) {
    if (!event.currentTarget.open || loaded || loading || importing) return;
    setLoading(true);
    setLoadError('');
    try {
      setCapture(await fetchLatestPassiveCapture(assessmentId));
      setLoaded(true);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : 'Could not load the latest capture.');
    } finally {
      setLoading(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || loading || importing) return;
    const form = event.currentTarget;
    setImporting(true);
    setImportError('');
    setNotice('');
    try {
      const body = await readBundle(file);
      setCapture(await importPassiveCapture(assessmentId, body));
      setLoaded(true);
      setLoadError('');
      form.reset();
      setFile(null);
      setNotice('Capture imported.');
    } catch (error) {
      setImportError(
        error instanceof Error ? error.message : 'Could not import the passive capture.',
      );
    } finally {
      setImporting(false);
    }
  }

  return (
    <details className={styles.panel} onToggle={loadLatest}>
      <summary>Import passive capture</summary>
      <form className={styles.form} onSubmit={submit}>
        <label htmlFor={inputId}>Signed capture bundle</label>
        <p id={`${inputId}-help`}>
          Choose the JSON export containing the redacted HAR, manifest, and signature.
        </p>
        <input
          id={inputId}
          name="capture"
          type="file"
          accept="application/json,.json"
          aria-describedby={`${inputId}-help`}
          disabled={importing}
          onChange={(event) => {
            setFile(event.currentTarget.files?.[0] ?? null);
            setImportError('');
            setNotice('');
          }}
        />
        <button type="submit" disabled={!file || loading || importing}>
          {importing ? 'Importing…' : 'Import capture'}
        </button>
        {importError && (
          <p className={styles.error} role="alert">
            {importError}
          </p>
        )}
        <p className={styles.notice} role="status">
          {notice}
        </p>
      </form>
      {loading && <p role="status">Loading latest capture…</p>}
      {loadError && (
        <p className={styles.error} role="alert">
          {loadError}
        </p>
      )}
      {capture ? (
        <CaptureResult capture={capture} />
      ) : (
        loaded && <p>No passive capture imported yet.</p>
      )}
    </details>
  );
}
