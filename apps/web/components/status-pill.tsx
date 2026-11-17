import type { JobStatus } from '@/lib/types';
import styles from './status-pill.module.css';

export function StatusPill({ status }: { status: JobStatus }) {
  return <span className={`${styles.status} ${styles[status]}`}>{status}</span>;
}
