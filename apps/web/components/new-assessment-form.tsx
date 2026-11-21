'use client';

import { useEffect, useState, type FormEvent } from 'react';
import type { AssessmentInput, ProjectReviewCatalog, ProjectReviewProvider } from '@/lib/types';
import { fetchReviewModels } from '@/lib/api';
import { normalizeUrl } from '@/lib/url-check';
import { MatrixOrb } from './matrix-orb';
import styles from './new-assessment-form.module.css';

interface NewAssessmentFormProps {
  disabled: boolean;
  error: string;
  message: string;
  onCreate: (input: AssessmentInput) => Promise<void>;
}

const providerNames = { qwencloud: 'QwenCloud (Singapore)', groq: 'Groq' };
const modelNames: Record<string, string> = {
  'qwen3.7-flash': 'Qwen 3.7 Flash',
  'openai/gpt-oss-20b': 'GPT OSS 20B',
};

const initialForm: AssessmentInput = {
  project_name: '',
  repository_path: '',
  target_url: '',
  source_type: 'zip',
  runtime_discovery_authorized: false,
};

export function NewAssessmentForm({ disabled, error, message, onCreate }: NewAssessmentFormProps) {
  const [form, setForm] = useState(initialForm);
  const [step, setStep] = useState<'source' | 'runtime' | 'ai'>('source');
  const [submitting, setSubmitting] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [draggingZip, setDraggingZip] = useState(false);
  const [catalog, setCatalog] = useState<ProjectReviewCatalog | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<ProjectReviewProvider>();
  const [consentedModel, setConsentedModel] = useState<string>();
  const [modelError, setModelError] = useState('');
  const [modelRetry, setModelRetry] = useState(0);
  const model =
    catalog?.models.find((entry) => entry.available && entry.provider === selectedProvider) ??
    catalog?.models.find((entry) => entry.available && entry.provider === catalog.preferred) ??
    catalog?.models.find((entry) => entry.available);

  const modelIdentity = model ? model.provider + ':' + model.model : undefined;
  const sharingApproved = Boolean(modelIdentity && consentedModel === modelIdentity);

  useEffect(() => {
    if (step !== 'ai') return;
    const controller = new AbortController();
    void fetchReviewModels(controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) {
          setCatalog(result);
          setModelError('');
        }
      })
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) {
          setCatalog(null);
          setModelError(cause instanceof Error ? cause.message : 'Could not load review models.');
        }
      });
    return () => controller.abort();
  }, [step, modelRetry]);

  const labOrigin = 'http://juiceshop:3000';
  let isLabUrl = false;
  try {
    isLabUrl = normalizeUrl(form.target_url) === labOrigin + '/';
  } catch {
    // The editable field may be empty or incomplete.
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    if (step === 'source' && (submitter?.value === 'runtime' || submitter?.value === 'ai')) {
      setStep(submitter.value);
      return;
    }

    const runtime = step === 'runtime';
    if (disabled || (runtime && (!isLabUrl || !form.runtime_discovery_authorized))) return;
    const ai = step === 'ai' && form.source_type === 'zip';
    if (step === 'ai' && (!ai || !sharingApproved)) return;

    setSubmitting(true);
    try {
      await onCreate({
        ...form,
        target_url: ai ? '' : labOrigin,
        runtime_discovery_authorized: runtime,
        ai_review_authorized: ai,
        ai_review_provider: ai ? model?.provider : undefined,
      });
    } finally {
      setSubmitting(false);
    }
  }

  function backToSource() {
    setForm({ ...form, runtime_discovery_authorized: false, ai_review_authorized: false });
    setConsentedModel(undefined);
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
              Target URL
              <input
                type="url"
                placeholder="http://juiceshop:3000"
                required
                value={form.target_url}
                aria-describedby="runtime-url-help"
                onChange={(event) => {
                  setForm({
                    ...form,
                    target_url: event.target.value,
                    runtime_discovery_authorized: false,
                  });
                }}
              />
              <span className={styles.guidance} id="runtime-url-help">
                Runtime discovery is available for the local Juice Shop at http://juiceshop:3000.
              </span>
            </label>
            {form.target_url.trim() && !isLabUrl && (
              <p className={styles.error} role="status">
                This URL is outside the configured discovery scope.
              </p>
            )}
            {isLabUrl && (
              <label className={styles.attestation}>
                <input
                  type="checkbox"
                  required
                  checked={form.runtime_discovery_authorized}
                  onChange={(event) =>
                    setForm({ ...form, runtime_discovery_authorized: event.target.checked })
                  }
                />
                <span>I am authorized to run read-only discovery on this local Juice Shop.</span>
              </label>
            )}
          </fieldset>
        )}
        {step === 'ai' && (
          <>
            <fieldset className={styles.modelPicker}>
              <legend>Choose a model</legend>
              {!catalog && !modelError && (
                <p role="status" className={styles.guidance}>
                  Loading available models…
                </p>
              )}
              {modelError && (
                <div className={styles.notice} role="alert">
                  <p>{modelError}</p>
                  <button
                    className={styles.secondaryButton}
                    type="button"
                    onClick={() => setModelRetry((attempt) => attempt + 1)}
                  >
                    Retry
                  </button>
                </div>
              )}
              <div className={styles.modelOptions}>
                {catalog?.models.map((entry) => {
                  const selected = entry.provider === model?.provider;
                  return (
                    <label
                      className={styles.modelOption}
                      key={entry.provider}
                      data-available={entry.available}
                    >
                      <span className={styles.orbStage} aria-hidden="true">
                        <MatrixOrb
                          color={entry.provider === 'qwencloud' ? '#49d48b' : '#f75001'}
                          size={148}
                          state={selected ? (submitting ? 'thinking' : 'listening') : 'idle'}
                          animated={selected && entry.available}
                        />
                      </span>
                      <span className={styles.modelRow}>
                        <span className={styles.modelMeta}>
                          <strong className={styles.modelName}>
                            {modelNames[entry.model] ?? entry.model}
                          </strong>
                          <span className={styles.modelProvider}>
                            {providerNames[entry.provider]}
                          </span>
                          {!entry.available && (
                            <span className={styles.modelProvider}>API key not configured</span>
                          )}
                        </span>
                        <input
                          className={styles.modelRadio}
                          type="radio"
                          name="review-model"
                          value={entry.provider}
                          checked={selected}
                          disabled={submitting || !entry.available}
                          onChange={() => {
                            setSelectedProvider(entry.provider);
                            setConsentedModel(undefined);
                          }}
                        />
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>
            <label className={styles.attestation}>
              <input
                type="checkbox"
                required
                disabled={submitting || !model}
                checked={sharingApproved}
                onChange={(event) =>
                  setConsentedModel(event.target.checked ? modelIdentity : undefined)
                }
              />
              <span>
                I approve sending supported project source files and scanner summaries to{' '}
                {model ? providerNames[model.provider] : 'the selected provider'}
                {model && <> using {model.model}</>} and saving the report with this assessment.
                Sapphire may keep a temporary copy of the ZIP for up to 48 hours so the review can
                continue across processing windows.
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
                disabled={
                  submitting ||
                  disabled ||
                  (step === 'ai' && !sharingApproved) ||
                  (step === 'runtime' && (!isLabUrl || !form.runtime_discovery_authorized))
                }
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
