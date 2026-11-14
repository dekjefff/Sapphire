'use client';

import type { Assessment } from '@/lib/types';
import { AssessmentCard } from './assessment-card';
import styles from './assessment-list.module.css';

interface AssessmentListProps {
  assessments: Assessment[];
  onRefresh: () => void;
}

export function AssessmentList({ assessments, onRefresh }: AssessmentListProps) {
  return (
    <section className={styles.panel} aria-labelledby="recent-assessments-title">
      <div className={styles.heading}>
        <div>
          <p className={styles.eyebrow}>ACTIVITY</p>
          <h2 id="recent-assessments-title">Recent assessments</h2>
        </div>
        <button
          className={styles.refresh}
          onClick={onRefresh}
          type="button"
          aria-label="Refresh assessments"
        >
          ↻
        </button>
      </div>
      {assessments.length === 0 ? (
        <div className={styles.empty}>
          <div className={styles.emptyIcon} aria-hidden="true">
            ⌁
          </div>
          <strong>No assessments yet</strong>
          <p>Create an assessment to start a dummy foundation job.</p>
        </div>
      ) : (
        <div className={styles.list}>
          {assessments.map((assessment) => (
            <AssessmentCard assessment={assessment} key={assessment.id} />
          ))}
        </div>
      )}
    </section>
  );
}
