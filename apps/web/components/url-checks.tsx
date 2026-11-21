'use client';

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { normalizeUrl } from '@/lib/url-check';
import { StatusPill } from './status-pill';
import styles from './url-checks.module.css';

type CheckResult = {
  status: 'completed' | 'failed' | 'incomplete';
  label: string;
  milliseconds: number;
};

export function UrlChecks({ storageScope }: { storageScope: string }) {
  const storageKey = 'sapphire.url-checks.' + storageScope;
  const [ready, setReady] = useState(false);
  const [urls, setUrls] = useState<string[]>([]);
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const [storageUnavailable, setStorageUnavailable] = useState(false);
  const [active, setActive] = useState<string>();
  const [results, setResults] = useState<Record<string, CheckResult>>({});
  const request = useRef<AbortController>(null);

  useEffect(() => {
    const valid = new Set<string>();
    let available = true;
    try {
      const saved: unknown = JSON.parse(window.localStorage.getItem(storageKey) ?? '[]');
      if (Array.isArray(saved)) {
        for (const url of saved) {
          if (typeof url !== 'string') continue;
          try {
            valid.add(normalizeUrl(url));
          } catch {
            continue;
          }
        }
      }
    } catch {
      available = false;
    }

    setStorageUnavailable(!available);
    setUrls([...valid]);
    setReady(true);
    return () => {
      const running = request.current;
      request.current = null;
      running?.abort();
    };
  }, [storageKey]);

  function save(next: string[]) {
    setUrls(next);
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(next));
      setStorageUnavailable(false);
    } catch {
      setStorageUnavailable(true);
    }
  }

  function addUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    setError('');
    try {
      const url = normalizeUrl(value);
      if (urls.includes(url)) {
        setError('This URL is already saved.');
        return;
      }
      save([...urls, url]);
      setValue('');
    } catch (cause) {
      setError(
        cause instanceof TypeError
          ? 'Enter a complete URL, such as https://example.com/health.'
          : (cause as Error).message,
      );
    }
  }

  function removeUrl(url: string) {
    save(urls.filter((item) => item !== url));
    setResults((current) => {
      const next = { ...current };
      delete next[url];
      return next;
    });
  }

  async function check(url: string) {
    if (request.current) return;
    const controller = new AbortController();
    request.current = controller;
    setActive(url);
    const start = performance.now();
    const timer = window.setTimeout(() => controller.abort(), 8000);

    let result: Pick<CheckResult, 'status' | 'label'>;
    try {
      const response = await fetch(url, {
        method: 'HEAD',
        mode: 'cors',
        redirect: 'manual',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
        signal: controller.signal,
      });
      result =
        response.type === 'opaqueredirect'
          ? { status: 'incomplete', label: 'Redirect returned' }
          : { status: response.ok ? 'completed' : 'failed', label: 'HTTP ' + response.status };
    } catch {
      result = controller.signal.aborted
        ? { status: 'incomplete', label: 'Timed out' }
        : { status: 'incomplete', label: 'Response unavailable to the browser' };
    } finally {
      window.clearTimeout(timer);
    }
    if (request.current !== controller) return;
    request.current = null;
    setResults((current) => ({
      ...current,
      [url]: { ...result, milliseconds: Math.round(performance.now() - start) },
    }));
    setActive(undefined);
  }

  return (
    <section id="workspace-url-checks" className={styles.panel} aria-labelledby="saved-url-heading">
      <h2 id="saved-url-heading">Saved URLs</h2>
      <p>
        Save a URL you are authorized to check. Each check uses one HEAD request from your browser.
      </p>
      <form className={styles.form} onSubmit={addUrl}>
        <label className={styles.field}>
          URL
          <input
            type="url"
            name="url"
            placeholder="https://example.com/health"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            required
          />
        </label>
        <button className="sapphire-primary-button" type="submit" disabled={!ready}>
          Add URL
        </button>
      </form>
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
      {storageUnavailable && (
        <p role="status">Browser storage is unavailable. URLs are saved for this visit only.</p>
      )}
      {ready && urls.length === 0 && <p>No URLs saved yet.</p>}
      {urls.length > 0 && (
        <ul className={styles.urls}>
          {urls.map((url) => {
            const result = results[url];
            return (
              <li key={url} className={styles.row}>
                <div className={styles.target}>
                  <strong>{url}</strong>
                  <div className={styles.result} aria-live="polite">
                    {active === url ? (
                      <StatusPill status="running" label="Checking…" />
                    ) : result ? (
                      <>
                        <StatusPill status={result.status} label={result.label} />
                        <span>{result.milliseconds} ms</span>
                      </>
                    ) : (
                      <span>Not checked yet</span>
                    )}
                  </div>
                </div>
                <div className={styles.actions}>
                  <button
                    className="sapphire-primary-button"
                    type="button"
                    disabled={Boolean(active)}
                    onClick={() => void check(url)}
                  >
                    Check URL
                  </button>
                  <button
                    className={styles.remove}
                    type="button"
                    disabled={active === url}
                    onClick={() => removeUrl(url)}
                  >
                    Remove
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      <p className={styles.note}>
        Saved URLs stay in this browser. For another origin, the site must allow this page through
        CORS to show an HTTP status. Redirects are reported without following them.
      </p>
    </section>
  );
}
