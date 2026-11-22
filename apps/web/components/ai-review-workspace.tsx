'use client';

import Link from 'next/link';
import type { Assessment } from '@/lib/types';
import { AiCodeReviewPanel } from './ai-code-review-panel';
import { ProjectCodeReview, reviewStatusLabel } from './project-code-review';
import styles from './review-workspace.module.css';

export function AiReviewWorkspace({
  assessments,
  reviewId,
  loading,
  onRefresh,
}: {
  assessments: Assessment[];
  reviewId?: string;
  loading: boolean;
  onRefresh: () => Promise<void>;
}) {
  const reviews = assessments.flatMap((assessment) =>
    assessment.ai_review ? [{ ...assessment, review: assessment.ai_review }] : [],
  );
  const selected = reviewId ? reviews.find(({ id }) => id === reviewId) : reviews[0];

  if (!loading && !reviewId && reviews.length === 0) {
    return (
      <div className={styles.surface}>
        <AiCodeReviewPanel />
      </div>
    );
  }

  return (
    <div className={styles.workspace}>
      <section className={styles.projects} aria-labelledby="review-projects">
        <h2 id="review-projects">Project reviews</h2>
        {loading && <p role="status">Loading project reviews…</p>}
        {reviews.length > 0 && (
          <nav aria-label="Project reviews">
            {reviews.map(({ id, project_name, review }) => (
              <Link
                key={id}
                href={`/ai-review?assessment=${encodeURIComponent(id)}`}
                aria-current={selected?.id === id ? 'page' : undefined}
              >
                <strong>{project_name}</strong>
                <span>{reviewStatusLabel(review)}</span>
              </Link>
            ))}
          </nav>
        )}
        {!loading && reviews.length === 0 && <p>No project reviews available.</p>}
      </section>
      <div className={styles.content}>
        {selected ? (
          <ProjectCodeReview
            key={selected.id}
            assessmentId={selected.id}
            projectName={selected.project_name}
            summary={selected.review}
            onRefresh={onRefresh}
          />
        ) : !loading && reviewId ? (
          <p role="status">This project review is not available in the current list.</p>
        ) : null}
        <details className={styles.surface}>
          <summary>Import a CLI report</summary>
          <AiCodeReviewPanel />
        </details>
      </div>
    </div>
  );
}
