'use client';

import { useState, type ReactNode } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { AppShell } from './app-shell';
import { AiReviewWorkspace } from './ai-review-workspace';
import { AssessmentCard } from './assessment-card';
import Image from 'next/image';
import { NewAssessmentForm } from './new-assessment-form';
import { useAssessments } from '@/hooks/use-assessments';
import type { AssessmentInput } from '@/lib/types';
import styles from './dashboard.module.css';

const sections = [
  { id: 'recent', label: 'Projects', title: 'Projects' },
  { id: 'new', label: 'New assessment', title: 'Create an assessment' },
] as const;

type DashboardProps = {
  account: ReactNode;
  reviewProvider: NonNullable<AssessmentInput['ai_review_provider']>;
  initialSection?: 'recent' | 'new' | 'review';
  reviewId?: string;
};

export function Dashboard({
  account,
  reviewProvider,
  initialSection = 'recent',
  reviewId,
}: DashboardProps) {
  const router = useRouter();
  const { health, assessments, loadError, createAssessment } = useAssessments();
  const [section, setSection] = useState(initialSection);
  const [submissionError, setSubmissionError] = useState('');
  const [submissionMessage, setSubmissionMessage] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = assessments.find(({ id }) => id === selectedId);
  const heading =
    section === 'review' ? 'AI Code Review' : sections.find(({ id }) => id === section)?.title;
  const [page, setPage] = useState(0);
  const pageSize = 6;
  const currentPage = Math.min(page, Math.max(0, Math.ceil(assessments.length / pageSize) - 1));

  async function handleCreate(input: AssessmentInput) {
    setSubmissionError('');
    setSubmissionMessage('');
    try {
      const created = await createAssessment(input);
      if (input.ai_review_authorized) {
        router.push(`/ai-review?assessment=${encodeURIComponent(created.assessment_id)}`);
      }
      const discovery =
        created.runtime_discovery?.status === 'authorized'
          ? 'Exact local discovery profile authorized.'
          : 'Runtime discovery was not authorized; no discovery requests will be queued.';
      setSubmissionMessage(
        `Assessment ${created.assessment_id} queued. Job ${created.job_id}. ${discovery}`,
      );
    } catch (error) {
      setSubmissionError(error instanceof Error ? error.message : 'Request failed');
    }
  }

  return (
    <AppShell
      account={account}
      navigation={
        <nav aria-label="Workspace sections" className={styles.menu}>
          <p className={styles.menuTitle}>Workspace</p>
          {sections.map(({ id, label }) =>
            section === 'review' ? (
              <Link key={id} href={id === 'recent' ? '/' : '/?section=new'}>
                {label}
              </Link>
            ) : (
              <button
                key={id}
                type="button"
                aria-pressed={section === id}
                aria-controls={`workspace-${id}`}
                onClick={() => {
                  setSelectedId(null);
                  setSection(id);
                }}
              >
                {label}
              </button>
            ),
          )}
          <Link href="/ai-review" aria-current={section === 'review' ? 'page' : undefined}>
            AI Code Review
          </Link>
        </nav>
      }
    >
      {!(section === 'recent' && selected) && (
        <div
          className={
            section === 'new'
              ? `${styles.pageHeader} ${styles.assessmentColumn}`
              : styles.pageHeader
          }
        >
          <h1 className={styles.heading}>{heading}</h1>
          {section === 'recent' && (
            <button type="button" className={styles.whiteButton} onClick={() => setSection('new')}>
              Create assessment
            </button>
          )}
        </div>
      )}
      {loadError && (
        <div className={section === 'new' ? styles.assessmentColumn : undefined}>
          <p className={styles.loadError} role="status">
            {loadError}
          </p>
        </div>
      )}

      <div id="workspace-new" className={styles.assessmentColumn} hidden={section !== 'new'}>
        <NewAssessmentForm
          reviewProvider={reviewProvider}
          disabled={health?.status !== 'ok'}
          error={submissionError}
          message={submissionMessage}
          onCreate={handleCreate}
        />
      </div>
      <div id="workspace-recent" hidden={section !== 'recent'}>
        {section === 'recent' &&
          (selected ? (
            <div className={styles.projectDetails}>
              <button
                type="button"
                className={styles.whiteButton}
                onClick={() => setSelectedId(null)}
              >
                Back to projects
              </button>
              <h1 className={styles.heading}>{selected.project_name}</h1>
              <AssessmentCard key={selected.id} assessment={selected} />
            </div>
          ) : assessments.length ? (
            <>
              <ul className={styles.folders} aria-label="Projects">
                {assessments
                  .slice(currentPage * pageSize, (currentPage + 1) * pageSize)
                  .map((assessment) => {
                    const status =
                      assessment.status === 'completed' &&
                      (assessment.coverage_status === 'incomplete' ||
                        assessment.ai_review?.status === 'incomplete')
                        ? 'incomplete'
                        : assessment.status;
                    return (
                      <li key={assessment.id}>
                        <button
                          type="button"
                          className={styles.folderButton}
                          onClick={() => setSelectedId(assessment.id)}
                        >
                          <Image
                            className={styles.folderArtwork}
                            src="/project-folder.svg"
                            width={190}
                            height={154}
                            alt=""
                            unoptimized
                          />
                          <span className={styles.projectName}>{assessment.project_name}</span>
                          <span className={styles.folderStatus} data-status={status}>
                            {status}
                          </span>
                        </button>
                      </li>
                    );
                  })}
              </ul>
              {assessments.length > pageSize && (
                <nav className={styles.pagination} aria-label="Project pages">
                  <button
                    type="button"
                    className={styles.whiteButton}
                    disabled={currentPage === 0}
                    onClick={() => setPage(currentPage - 1)}
                  >
                    Previous
                  </button>
                  <span>
                    {currentPage + 1} / {Math.ceil(assessments.length / pageSize)}
                  </span>
                  <button
                    type="button"
                    className={styles.whiteButton}
                    disabled={(currentPage + 1) * pageSize >= assessments.length}
                    onClick={() => setPage(currentPage + 1)}
                  >
                    Next
                  </button>
                </nav>
              )}
            </>
          ) : null)}
      </div>
      {section === 'review' && (
        <AiReviewWorkspace
          assessments={assessments}
          reviewId={reviewId}
          loading={!health && !loadError}
        />
      )}
    </AppShell>
  );
}
