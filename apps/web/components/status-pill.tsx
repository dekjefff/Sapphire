import styles from './status-pill.module.css';

function title(value: string) {
  const text = value.replaceAll('_', ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

const statusTones: Record<string, string> = {
  completed: 'success',
  complete: 'success',
  passed: 'success',
  queued: 'gray',
  pending: 'warning',
  incomplete: 'orange',
  partial: 'yellow',
  paused: 'warning',
  pausing: 'warning',
  waiting_for_scans: 'warning',
  running: 'blue',
  failed: 'danger',
  cancelled: 'danger',
  stopping: 'danger',
};
const severityTones: Record<string, string> = {
  critical: 'danger',
  high: 'high',
  medium: 'warning',
  moderate: 'warning',
  low: 'blue',
};

export function StatusPill({
  status,
  label,
  prefix,
  prominent = false,
}: {
  status: string;
  label?: string;
  prefix?: string;
  prominent?: boolean;
}) {
  const tone = statusTones[status] ?? 'neutral';
  return (
    <span className={styles.badge} data-tone={tone} data-prominent={prominent || undefined}>
      <span className={styles.dot} aria-hidden="true" />
      {prefix ? prefix + ': ' : ''}
      {label ?? title(status)}
    </span>
  );
}

export function SeverityPill({ level, count }: { level: string; count?: number }) {
  return (
    <span className={styles.badge} data-tone={severityTones[level] ?? 'neutral'}>
      {level === 'moderate' ? 'Medium' : title(level)}
      {count === undefined ? '' : ': ' + count}
    </span>
  );
}
