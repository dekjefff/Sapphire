'use client';

import { useState, type FormEvent } from 'react';
import type { AssessmentInput } from '@/lib/types';
import styles from './new-assessment-form.module.css';

interface NewAssessmentFormProps {
  reviewProvider: NonNullable<AssessmentInput['ai_review_provider']>;
  disabled: boolean;
  error: string;
  message: string;
  onCreate: (input: AssessmentInput) => Promise<void>;
}

const initialForm: AssessmentInput = {
  project_name: '',
  repository_path: '',
  target_url: '',
  source_type: 'zip',
  runtime_discovery_authorized: false,
};

export function NewAssessmentForm({
  reviewProvider,
  disabled,
  error,
  message,
  onCreate,
}: NewAssessmentFormProps) {
  const [form, setForm] = useState(initialForm);
  const [step, setStep] = useState<'source' | 'runtime' | 'ai'>('source');
  const [discoveryProfile, setDiscoveryProfile] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [draggingZip, setDraggingZip] = useState(false);
  const labOrigin = 'http://juiceshop:3000';

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    if (step === 'source' && (submitter?.value === 'runtime' || submitter?.value === 'ai')) {
      setStep(submitter.value);
      return;
    }

    if (disabled) return;
    const runtime = step === 'runtime';
    const ai = step === 'ai' && form.source_type === 'zip';
    if (
      runtime &&
      (!discoveryProfile || !form.runtime_discovery_authorized || form.target_url !== labOrigin)
    )
      return;
    if (step === 'ai' && (!ai || !form.ai_review_authorized)) return;

    setSubmitting(true);
    try {
      await onCreate({
        ...form,
        target_url: runtime ? form.target_url : ai ? '' : labOrigin,
        runtime_discovery_authorized: runtime,
        ai_review_authorized: ai,
        ai_review_provider: ai ? reviewProvider : undefined,
      });
    } finally {
      setSubmitting(false);
    }
  }

  function backToSource() {
    setForm({ ...form, runtime_discovery_authorized: false, ai_review_authorized: false });
    setStep('source');
  }

  function updateZip(input: HTMLInputElement, files: FileList | null) {
    const file = files?.[0];
    let issue = '';
    if (files && files.length > 1) issue = 'Choose one ZIP archive.';
    else if (file && !/\.zip$/i.test(file.name)) issue = 'Choose a ZIP archive.';
    else if (file && file.size > 100 * 1024 * 1024) issue = 'The ZIP must be 100 MB or smaller.';

    if (issue) input.value = '';
    else if (files && files !== input.files) input.files = files;
    input.setCustomValidity(issue);
    setUploadError(issue);
    setForm((current) => ({ ...current, source_file: issue ? undefined : file }));
  }

  return (
    <section
      className={styles.panel}
      data-step={step}
      aria-labelledby={step === 'source' ? 'assessment-source-title' : 'new-assessment-title'}
    >
      {step !== 'source' && (
        <h2 className={styles.sectionHeading} id="new-assessment-title">
          {step === 'runtime' ? 'Runtime discovery' : 'AI code review'}
        </h2>
      )}

      <form onSubmit={handleSubmit}>
        <fieldset
          className={styles.fields}
          hidden={step !== 'source'}
          disabled={step !== 'source' || submitting}
        >
          <label>
            <span className={styles.sectionHeading}>Project name</span>
            <input
              required
              maxLength={120}
              value={form.project_name}
              onChange={(event) => setForm({ ...form, project_name: event.target.value })}
              placeholder="e.g. Payments service"
            />
          </label>
          <div className={styles.sourceHeader}>
            <h2 className={styles.sectionHeading} id="assessment-source-title">
              Project source
            </h2>
            <div className={styles.sourceToggle} role="group" aria-label="Source type">
              {(['zip', 'local_path'] as const).map((source) => (
                <button
                  key={source}
                  type="button"
                  aria-pressed={form.source_type === source}
                  onClick={() => {
                    if (form.source_type === source) return;
                    setUploadError('');
                    setDraggingZip(false);
                    setForm({
                      ...form,
                      source_type: source,
                      source_file: undefined,
                      ai_review_authorized: false,
                    });
                  }}
                >
                  {source === 'zip' ? 'ZIP upload' : 'Mounted repository'}
                </button>
              ))}
            </div>
          </div>
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
              <span className={styles.guidance}>
                Use an absolute path inside a configured workspace root mounted into the API and
                worker.
              </span>
            </label>
          ) : (
            <div className={styles.uploadField}>
              <label htmlFor="assessment-zip">Repository ZIP</label>
              <div className={styles.uploadBox} data-dragging={draggingZip && !submitting}>
                <input
                  id="assessment-zip"
                  className={styles.fileInput}
                  aria-describedby={
                    uploadError
                      ? 'assessment-zip-error assessment-zip-guidance'
                      : 'assessment-zip-guidance'
                  }
                  aria-invalid={Boolean(uploadError)}
                  required
                  type="file"
                  accept=".zip,application/zip"
                  onChange={(event) => updateZip(event.currentTarget, event.currentTarget.files)}
                  onDragOver={(event) => {
                    if (!event.dataTransfer.types.includes('Files')) return;
                    event.preventDefault();
                    const enabled = !event.currentTarget.matches(':disabled');
                    event.dataTransfer.dropEffect = enabled ? 'copy' : 'none';
                    setDraggingZip(enabled);
                  }}
                  onDragLeave={() => setDraggingZip(false)}
                  onDrop={(event) => {
                    event.preventDefault();
                    setDraggingZip(false);
                    const { files } = event.dataTransfer;
                    if (files.length > 0 && !event.currentTarget.matches(':disabled')) {
                      updateZip(event.currentTarget, files);
                    }
                  }}
                />
                <span className={styles.uploadPrompt} aria-hidden="true">
                  {draggingZip && !submitting ? (
                    <strong>Release to drop the ZIP</strong>
                  ) : form.source_file ? (
                    <strong>{form.source_file.name}</strong>
                  ) : (
                    <strong>Drop your project ZIP here</strong>
                  )}
                  <span>
                    {draggingZip
                      ? 'One ZIP, up to 100 MB'
                      : form.source_file
                        ? 'ZIP selected'
                        : 'One ZIP, up to 100 MB'}
                  </span>
                  {!draggingZip && (
                    <span className={styles.browse}>
                      {form.source_file ? 'Replace file' : 'Browse files'}
                    </span>
                  )}
                </span>
              </div>
              {uploadError && (
                <p
                  className={`${styles.notice} ${styles.error}`}
                  id="assessment-zip-error"
                  role="alert"
                >
                  {uploadError}
                </p>
              )}
              <div className={styles.guidance} id="assessment-zip-guidance">
                <strong>ZIP contents</strong>
                Include source files and manifests. Leave out dependencies, build output, Git
                metadata, and links.
                <details className={styles.archiveDetails}>
                  <summary>Archive limits and exclusions</summary>
                  <p>
                    Omit folders such as node_modules, .git, .next, dist, build, and vendor, plus
                    symlinks and junctions. Recognized items are skipped and reported. The ZIP can
                    contain up to 250 MB expanded, 20,000 files, and 10 MB per file. Malformed
                    archives, traversal paths, and special entries are rejected.
                  </p>
                </details>
              </div>
            </div>
          )}
        </fieldset>
        {step === 'runtime' && (
          <fieldset className={styles.fields} disabled={submitting}>
            <label>
              Runtime discovery profile
              <select
                required
                value={discoveryProfile}
                onChange={(event) => {
                  const profile = event.target.value;
                  setDiscoveryProfile(profile);
                  setForm({
                    ...form,
                    target_url: profile ? labOrigin : '',
                    runtime_discovery_authorized: false,
                  });
                }}
              >
                <option value="">Choose a profile</option>
                <option value="juiceshop">Isolated local Juice Shop</option>
              </select>
              <span className={styles.guidance}>
                This profile uses bounded, read-only discovery on the configured local origin.
              </span>
            </label>
            {discoveryProfile && (
              <label>
                Target URL
                <input type="url" value={form.target_url} readOnly />
              </label>
            )}
            <label className={styles.attestation}>
              <input
                type="checkbox"
                required
                checked={form.runtime_discovery_authorized}
                disabled={!discoveryProfile}
                onChange={(event) =>
                  setForm({ ...form, runtime_discovery_authorized: event.target.checked })
                }
              />
              <span>
                I am authorized to run bounded discovery against this exact isolated local origin.
              </span>
            </label>
          </fieldset>
        )}
        {step === 'ai' && (
          <>
            <p className={styles.guidance}>
              Review what source data is sent to the configured AI provider before continuing.
            </p>
            <label className={styles.attestation}>
              <input
                type="checkbox"
                required
                disabled={submitting}
                checked={form.ai_review_authorized === true}
                onChange={(event) =>
                  setForm({ ...form, ai_review_authorized: event.target.checked })
                }
              />
              <span>
                I approve sending supported project source files and scanner summaries to{' '}
                {reviewProvider === 'qwencloud' ? 'QwenCloud (Singapore)' : 'Groq'} and saving the
                report with this assessment. Sapphire may keep a temporary copy of the ZIP for up to
                48 hours so the review can continue across processing windows.
              </span>
            </label>
          </>
        )}

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
        <div className={styles.actions}>
          {step === 'source' ? (
            <>
              <button
                className={styles.secondaryButton}
                type="submit"
                value="runtime"
                disabled={submitting}
              >
                Include URL discovery
              </button>
              <button
                className={styles.secondaryButton}
                type="submit"
                value="ai"
                disabled={submitting || form.source_type !== 'zip'}
              >
                Prefer AI code review
              </button>
              <button
                className={styles.primaryButton}
                type="submit"
                value="source"
                disabled={submitting || disabled}
              >
                {submitting ? 'Creating…' : 'Start assessment only'}
              </button>
            </>
          ) : (
            <>
              <button
                className={styles.secondaryButton}
                type="button"
                disabled={submitting}
                onClick={(event) => {
                  event.preventDefault();
                  backToSource();
                }}
              >
                Back
              </button>
              <button
                className={styles.primaryButton}
                type="submit"
                disabled={submitting || disabled}
              >
                {submitting
                  ? 'Creating…'
                  : step === 'runtime'
                    ? 'Start with URL discovery'
                    : 'Start AI code review'}
              </button>
            </>
          )}
        </div>
        {step === 'source' && form.source_type !== 'zip' && (
          <p className={`${styles.guidance} ${styles.warning}`}>
            AI code review requires a ZIP upload.
          </p>
        )}
      </form>
    </section>
  );
}
