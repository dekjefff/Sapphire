'use client';

import { useState, type FormEvent } from 'react';
import type { AssessmentInput } from '@/lib/types';
import styles from './new-assessment-form.module.css';

interface NewAssessmentFormProps {
  disabled: boolean;
  error: string;
  message: string;
  onCreate: (input: AssessmentInput) => Promise<void>;
}

const initialForm: AssessmentInput = {
  project_name: 'Juice Shop demo',
  repository_path: '/workspace',
  target_url: 'http://juiceshop:3000',
  source_type: 'local_path',
  runtime_discovery_authorized: false,
};

export function NewAssessmentForm({ disabled, error, message, onCreate }: NewAssessmentFormProps) {
  const [form, setForm] = useState(initialForm);
  const [discoveryProfile, setDiscoveryProfile] = useState<'none' | 'juiceshop'>('none');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await onCreate(form);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className={styles.panel} aria-labelledby="new-assessment-title">
      <div className={styles.sectionHead}>
        <div className={styles.step} aria-hidden="true">
          01
        </div>
        <div>
          <h2 id="new-assessment-title">New assessment</h2>
          <p>Choose a local repository folder or a ZIP archive.</p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <label>
          Project name
          <input
            required
            maxLength={120}
            value={form.project_name}
            onChange={(event) => setForm({ ...form, project_name: event.target.value })}
            placeholder="e.g. Payments service"
          />
        </label>
        <label>
          Source type
          <select
            value={form.source_type}
            onChange={(event) =>
              setForm({
                ...form,
                source_type: event.target.value as 'local_path' | 'zip',
                source_file: undefined,
              })
            }
          >
            <option value="local_path">Mounted local repository</option>
            <option value="zip">ZIP upload (up to 100 MB)</option>
          </select>
        </label>
        {form.source_type === 'local_path' ? (
          <label>
            Repository path
            <input
              required
              maxLength={2048}
              value={form.repository_path}
              onChange={(event) => setForm({ ...form, repository_path: event.target.value })}
              placeholder="/workspace/my-repository"
            />
            <span className={styles.hint}>
              Use an absolute path inside a configured workspace root mounted into the API and
              worker.
            </span>
          </label>
        ) : (
          <label>
            Repository ZIP
            <input
              required
              type="file"
              accept=".zip,application/zip"
              onChange={(event) => setForm({ ...form, source_file: event.target.files?.[0] })}
            />
            <span className={styles.hint}>
              Include source files and manifests. Leave out node_modules, .git, generated folders
              (.next, dist, build, vendor), symlinks, and junctions. Known generated/dependency
              folders and recognized links are skipped before extraction and reported with a bounded
              list and total count; a truncated list is marked. Traversal, special entries,
              malformed archives, and inputs over 100 MB ZIP, 250 MB expanded, 20,000 files, or 10
              MB/file are rejected.
            </span>
          </label>
        )}
        <label>
          Target URL
          <input
            required
            type="url"
            value={discoveryProfile === 'juiceshop' ? 'http://juiceshop:3000' : form.target_url}
            readOnly={discoveryProfile === 'juiceshop'}
            onChange={(event) => setForm({ ...form, target_url: event.target.value })}
            placeholder="http://juiceshop:3000"
          />
          <span className={styles.hint}>
            Enter the exact target origin you are authorized to assess. Runtime discovery is limited
            to the selected exact profile; no public or third-party targets are supported.
          </span>
        </label>
        <label>
          Runtime discovery profile
          <select
            value={discoveryProfile}
            onChange={(event) => {
              const profile = event.target.value as 'none' | 'juiceshop';
              setDiscoveryProfile(profile);
              setForm({
                ...form,
                target_url: profile === 'juiceshop' ? 'http://juiceshop:3000' : form.target_url,
                runtime_discovery_authorized: false,
              });
            }}
          >
            <option value="none">Static intake only (default)</option>
            <option value="juiceshop">Isolated local Juice Shop · http://juiceshop:3000</option>
          </select>
          <span className={styles.hint}>
            The local-test profile is a whole-origin HTTP scope with GET only. Requests use fixed
            limits: depth 3, up to 500 URLs, 1 request/second per host, 1 MiB per response, 50 MiB
            total, and 120 seconds. Redirects are not followed; login, cookies, forms, and
            state-changing requests are excluded.
          </span>
        </label>
        <label className={styles.attestation}>
          <input
            type="checkbox"
            checked={form.runtime_discovery_authorized}
            disabled={discoveryProfile !== 'juiceshop'}
            onChange={(event) =>
              setForm({ ...form, runtime_discovery_authorized: event.target.checked })
            }
          />
          <span>
            I am authorized to run this bounded discovery against the exact target shown above. I
            confirm this is the isolated local Juice Shop profile and will not test a public or
            third-party target.
          </span>
        </label>

        {error && (
          <div className={`${styles.notice} ${styles.error}`} role="alert">
            {error}
          </div>
        )}
        {message && (
          <div className={`${styles.notice} ${styles.success}`} role="status">
            {message}
          </div>
        )}
        <button className={styles.primaryButton} disabled={submitting || disabled} type="submit">
          {submitting ? 'Creating…' : 'Create assessment'}
          <span aria-hidden="true">→</span>
        </button>
      </form>
    </section>
  );
}
