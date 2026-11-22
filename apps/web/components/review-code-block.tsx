'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';
import styles from './review-code-block.module.css';

const keywords = new Set(
  'import from export default async function const let var await return if else for while new throw try catch null true false undefined class def elif None True False fn pub func struct package using public private static void int bool string'.split(
    ' ',
  ),
);

const token = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`|\b\d+(?:\.\d+)?\b|[A-Za-z_$][\w$]*)/g;

function highlight(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let end = 0;
  for (const match of text.matchAll(token)) {
    const word = match[0];
    const start = match.index;
    if (start > end) nodes.push(text.slice(end, start));
    end = start + word.length;
    const style = /^["'`\d]/.test(word)
      ? styles.literal
      : keywords.has(word)
        ? styles.keyword
        : /^\s*\(/.test(text.slice(end))
          ? styles.functionName
          : undefined;
    nodes.push(
      style ? (
        <span key={start} className={style}>
          {word}
        </span>
      ) : (
        word
      ),
    );
  }
  if (end < text.length) nodes.push(text.slice(end));
  return nodes;
}

export function ReviewCodeBlock({
  file,
  firstLine,
  citedLine,
  evidence,
}: {
  file: string;
  firstLine: number;
  citedLine: number;
  evidence: string;
}) {
  const bodyRef = useRef<HTMLPreElement>(null);
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'error'>('idle');
  const filename = file.split(/[/\\]/).at(-1) || file;
  const lines = evidence.split(/\r\n|\n|\r/);

  useEffect(() => {
    if (copyStatus === 'idle') return;
    const timer = window.setTimeout(() => setCopyStatus('idle'), 2000);
    return () => window.clearTimeout(timer);
  }, [copyStatus]);

  useEffect(() => {
    const body = bodyRef.current;
    if (!body) return;

    function revealCitation() {
      const line = body?.querySelector('[data-cited]');
      if (!body?.clientHeight || !line) return;
      const viewport = body.getBoundingClientRect();
      const row = line.getBoundingClientRect();
      if (row.top < viewport.top || row.bottom > viewport.bottom) {
        body.scrollTop += row.top - viewport.top - body.clientHeight / 3;
      }
    }

    const details = body.closest('details');
    details?.addEventListener('toggle', revealCitation);
    revealCitation();
    return () => details?.removeEventListener('toggle', revealCitation);
  }, [citedLine, evidence]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(evidence);
      setCopyStatus('copied');
    } catch {
      setCopyStatus('error');
    }
  }

  return (
    <section className={styles.block} aria-label="Source evidence">
      <div className={styles.header}>
        <span className={styles.filename} title={file}>
          <svg
            aria-hidden="true"
            width="15"
            height="15"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="m17.25 6.75 5.25 5.25-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
          </svg>
          <span>{filename}</span>
        </span>
        <button
          className={styles.copy}
          type="button"
          data-status={copyStatus}
          onClick={() => void copy()}
        >
          <svg
            aria-hidden="true"
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            {copyStatus === 'copied' ? (
              <path d="m20 6-11 11-5-5" />
            ) : (
              <>
                <rect x="8" y="8" width="12" height="12" rx="2" />
                <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
              </>
            )}
          </svg>
          {copyStatus === 'copied' ? 'Copied' : 'Copy'}
        </button>
        <span className={styles.announcement} role="status">
          {copyStatus === 'copied'
            ? 'Code copied.'
            : copyStatus === 'error'
              ? 'Could not copy code.'
              : ''}
        </span>
      </div>
      <pre className={styles.body} ref={bodyRef}>
        <code>
          {lines.map((line, index) => (
            <span
              className={styles.line}
              key={firstLine + index}
              data-cited={firstLine + index === citedLine || undefined}
            >
              <span
                className={styles.number}
                aria-hidden="true"
                title={firstLine + index === citedLine ? 'Cited line' : undefined}
              >
                {firstLine + index}
              </span>
              <span className={styles.source}>{highlight(line)}</span>
            </span>
          ))}
        </code>
      </pre>
    </section>
  );
}
