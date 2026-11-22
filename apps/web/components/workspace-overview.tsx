'use client';

import { useEffect, useState, type KeyboardEvent } from 'react';
import { fetchWorkspaceOverview } from '@/lib/api';
import type { WorkspaceOverview as OverviewData } from '@/lib/types';
import styles from './workspace-overview.module.css';

const number = new Intl.NumberFormat('en-US');
const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const monthLabel = new Intl.DateTimeFormat('en-US', { month: 'short', timeZone: 'UTC' });
const dateLabel = new Intl.DateTimeFormat('en-US', { dateStyle: 'full', timeZone: 'UTC' });
const dateValue = (date: string) => new Date(date + 'T00:00:00Z');

function duration(seconds: number) {
  const minutes = Math.floor(seconds / 60);
  if (minutes === 0) return number.format(Math.floor(seconds)) + 's';
  const hours = Math.floor(minutes / 60);
  return hours ? number.format(hours) + 'h ' + (minutes % 60) + 'm' : minutes + 'm';
}

export function WorkspaceOverview() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    async function refresh() {
      try {
        const result = await fetchWorkspaceOverview(controller.signal);
        if (!controller.signal.aborted) {
          setData(result);
          setError('');
        }
      } catch (cause) {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : 'Overview is unavailable.');
        }
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [attempt]);

  const totals = data?.totals;
  return (
    <div id="workspace-overview" className={styles.overview}>
      {error && (
        <div className={styles.error} role="alert">
          <span>{error}</span>
          <button type="button" onClick={() => setAttempt((value) => value + 1)}>
            Retry
          </button>
        </div>
      )}
      {!totals && !error && <p role="status">Loading workspace metrics…</p>}
      {totals && data && (
        <>
          <section aria-label="Workspace totals" className={styles.metrics}>
            <Metric
              label="Projects scanned"
              value={number.format(totals.projects_scanned)}
              detail={number.format(totals.assessments) + ' assessments created'}
            />
            <Metric
              label="Scan findings"
              value={number.format(totals.findings)}
              detail={number.format(totals.high) + ' high severity'}
            />
            <Metric
              label="Critical findings"
              value={number.format(totals.critical)}
              detail="Across all scan results"
              critical={totals.critical > 0}
            />
            <Metric
              label="Scan time"
              value={duration(totals.scan_seconds)}
              detail={number.format(totals.scans) + ' finished tool runs'}
            />
            <Metric
              label="AI tokens used"
              value={number.format(totals.tokens)}
              detail="Reported by AI providers"
            />
            <Metric
              label="AI reviews"
              value={number.format(totals.reviews)}
              detail={
                number.format(totals.reviews_completed) +
                ' completed · ' +
                number.format(totals.ai_requests) +
                ' requests'
              }
            />
          </section>
          <Activity
            days={data.days}
            tokensWithoutDay={totals.tokens_without_day}
            timeZone={data.time_zone}
          />
        </>
      )}
    </div>
  );
}

function Metric({
  label,
  value,
  detail,
  critical,
}: {
  label: string;
  value: string;
  detail: string;
  critical?: boolean;
}) {
  return (
    <article className={styles.metric} data-critical={critical || undefined}>
      <h2>{label}</h2>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  );
}

const modes = [
  ['combined', 'Combined'],
  ['scans', 'Scans'],
  ['tokens', 'AI tokens'],
] as const;
type ActivityMode = (typeof modes)[number][0];

function Activity({
  days,
  timeZone,
  tokensWithoutDay,
}: {
  days: OverviewData['days'];
  timeZone: string;
  tokensWithoutDay: number;
}) {
  const [mode, setMode] = useState<ActivityMode>('combined');
  const [selectedDay, setSelectedDay] = useState<string>();
  if (!days.length) return null;

  const startOffset = dateValue(days[0].date).getUTCDay();
  const gridColumns = Math.ceil((days.length + startOffset) / 7);
  const maxScans = Math.max(1, ...days.map((day) => day.scans));
  const maxTokens = Math.max(1, ...days.map((day) => day.tokens));
  const activeDays = days.filter((day) => day.scans > 0 || day.tokens > 0);
  const currentDay =
    days.find((day) => day.date === selectedDay) ?? activeDays.at(-1) ?? days.at(-1)!;
  const months = new Map<number, string>();
  days.forEach((day, index) => {
    const date = dateValue(day.date);
    if (index === 0 || date.getUTCDate() === 1) {
      const column = Math.floor((index + startOffset) / 7) + 1;
      if (column <= gridColumns - 2) months.set(column, monthLabel.format(date));
    }
  });

  function focusNeighbor(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const offsets: Record<string, number | undefined> = {
      ArrowLeft: -7,
      ArrowRight: 7,
      ArrowUp: -1,
      ArrowDown: 1,
    };
    const delta = offsets[event.key];
    if (delta === undefined) return;
    event.preventDefault();
    const next = days[index + delta];
    if (next)
      event.currentTarget.parentElement
        ?.querySelector<HTMLButtonElement>('[data-day="' + next.date + '"]')
        ?.focus();
  }

  return (
    <section className={styles.activity} aria-labelledby="workspace-activity">
      <div className={styles.activityHeader}>
        <div>
          <h2 id="workspace-activity">Workspace activity</h2>
          <p>{number.format(activeDays.length)} active days in the last 365 days</p>
        </div>
        <div className={styles.switcher} role="group" aria-label="Activity metric">
          {modes.map(([id, label]) => (
            <button type="button" key={id} aria-pressed={id === mode} onClick={() => setMode(id)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className={styles.scroll}>
        <div
          className={styles.calendar}
          style={{ gridTemplateColumns: '32px repeat(' + gridColumns + ', minmax(10px, 1fr))' }}
        >
          {[...months].map(([column, month]) => (
            <span className={styles.month} key={column} style={{ gridColumn: column + 1 }}>
              {month}
            </span>
          ))}
          {weekday.map(
            (day, index) =>
              index % 2 === 1 && (
                <span className={styles.weekday} key={day} style={{ gridRow: index + 2 }}>
                  {day}
                </span>
              ),
          )}
          {days.map((day, index) => {
            const scanIntensity = day.scans / maxScans;
            const tokenIntensity = day.tokens / maxTokens;
            const intensity =
              mode === 'scans'
                ? scanIntensity
                : mode === 'tokens'
                  ? tokenIntensity
                  : Math.max(scanIntensity, tokenIntensity);
            const label =
              dateLabel.format(dateValue(day.date)) +
              ': ' +
              number.format(day.scans) +
              ' scans, ' +
              number.format(day.tokens) +
              ' AI tokens';
            return (
              <button
                key={day.date}
                className={styles.cell}
                type="button"
                data-level={Math.ceil(intensity * 4)}
                data-day={day.date}
                aria-label={label}
                title={label}
                aria-pressed={day.date === currentDay.date}
                tabIndex={day.date === currentDay.date ? 0 : -1}
                onFocus={() => setSelectedDay(day.date)}
                onClick={() => setSelectedDay(day.date)}
                onKeyDown={(event) => focusNeighbor(event, index)}
                style={{
                  gridColumn: Math.floor((index + startOffset) / 7) + 2,
                  gridRow: ((index + startOffset) % 7) + 2,
                }}
              />
            );
          })}
        </div>
      </div>
      <div className={styles.activityFooter}>
        <p className={styles.daySummary} aria-live="polite">
          <strong>{dateLabel.format(dateValue(currentDay.date))}</strong>
          <span>
            {number.format(currentDay.scans)} scans · {number.format(currentDay.tokens)} AI tokens
          </span>
        </p>
        <div className={styles.legend} aria-label="Activity intensity from less to more">
          <span>Less</span>
          {[0, 1, 2, 3, 4].map((level) => (
            <i key={level} data-level={level} aria-hidden="true" />
          ))}
          <span>More</span>
        </div>
      </div>
      <p className={styles.caption}>
        {timeZone} · Activity reflects finished scan runs and provider-reported AI tokens.
        {tokensWithoutDay > 0 && ' Older tokens with no recorded date appear in the total only.'}
      </p>
    </section>
  );
}
