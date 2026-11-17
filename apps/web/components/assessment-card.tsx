import type { Assessment } from '@/lib/types';
import { StatusPill } from './status-pill';
import styles from './assessment-card.module.css';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export function AssessmentCard({ assessment }: { assessment: Assessment }) {
  const status = assessment.job?.status ?? assessment.status;

  return (
    <article className={styles.card}>
      <div className={styles.top}>
        <div className={styles.avatar} aria-hidden="true">
          {assessment.project_name.slice(0, 1).toUpperCase()}
        </div>
        <div className={styles.title}>
          <strong>{assessment.project_name}</strong>
          <small>{assessment.target_url}</small>
        </div>
        <StatusPill status={status} />
      </div>
      <div className={styles.meta}>
        <span>Assessment</span>
        <code>{assessment.id.slice(0, 8)}</code>
        <span className={styles.dot}>·</span>
        <time dateTime={assessment.created_at}>
          {new Date(assessment.created_at).toLocaleString()}
        </time>
      </div>
      <a href={`${API_URL}/assessments/${assessment.id}`} target="_blank" rel="noreferrer">
        View assessment details <span aria-hidden="true">↗</span>
      </a>
    </article>
  );
}
