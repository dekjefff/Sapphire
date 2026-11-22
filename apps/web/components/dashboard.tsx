'use client';

import { useState, type ReactNode } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { AppShell } from './app-shell';
import { WorkspaceOverview } from './workspace-overview';
import { UrlChecks } from './url-checks';
import { AiReviewWorkspace } from './ai-review-workspace';
import { AssessmentCard } from './assessment-card';
import { StatusPill } from './status-pill';
import Image from 'next/image';
import { NewAssessmentForm } from './new-assessment-form';
import { useAssessments } from '@/hooks/use-assessments';
import type { AssessmentInput } from '@/lib/types';
import styles from './dashboard.module.css';

const sections = [
  { id: 'overview', label: 'Overview', title: 'Overview' },
  { id: 'recent', label: 'Projects', title: 'Projects' },
  { id: 'new', label: 'New assessment', title: 'Create an assessment' },
] as const;

type DashboardProps = {
  account: ReactNode;
  initialSection?: 'overview' | 'recent' | 'new' | 'review' | 'url-checks';
  reviewId?: string;
  urlCheckScope: string;
};

export function Dashboard({
  account,
  initialSection = 'overview',
  reviewId,
  urlCheckScope,
}: DashboardProps) {
  const router = useRouter();
  const { health, assessments, loadError, createAssessment, refresh } = useAssessments();
  const [section, setSection] = useState(initialSection);
  const [submissionError, setSubmissionError] = useState('');
  const [submissionMessage, setSubmissionMessage] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = assessments.find(({ id }) => id === selectedId);
  const heading =
    section === 'review'
      ? 'AI Code Review'
      : section === 'url-checks'
        ? 'URL checks'
        : sections.find(({ id }) => id === section)?.title;
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
            initialSection === 'review' || initialSection === 'url-checks' ? (
              <Link
                key={id}
                href={
                  id === 'overview' ? '/' : id === 'recent' ? '/?section=projects' : '/?section=new'
                }
              >
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
          <Link href="/url-checks" aria-current={section === 'url-checks' ? 'page' : undefined}>
            URL checks
          </Link>
        </nav>
      }
    >
      {!(section === 'recent' && selected) && (
        <div
          className={
            section === 'new'
              ? `${styles.pageHeader} ${styles.assessmentColumn}`
              : section === 'recent'
                ? `${styles.pageHeader} ${styles.projectsColumn}`
                : styles.pageHeader
          }
        >
          <h1 className={styles.heading}>{heading}</h1>
          {section === 'recent' && (
            <button
              type="button"
              className="sapphire-primary-button"
              onClick={() => setSection('new')}
            >
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

      {section === 'overview' && <WorkspaceOverview />}
      {section === 'url-checks' && <UrlChecks storageScope={urlCheckScope} />}
      <div id="workspace-new" className={styles.assessmentColumn} hidden={section !== 'new'}>
        <NewAssessmentForm
          disabled={health?.status !== 'ok'}
          error={submissionError}
          message={submissionMessage}
          onCreate={handleCreate}
        />
      </div>
      <div
        id="workspace-recent"
        className={selected ? undefined : styles.projectsColumn}
        hidden={section !== 'recent'}
      >
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
                            width={216}
                            height={175}
                            alt=""
                            unoptimized
                          />
                          <span className={styles.projectName} title={assessment.project_name}>
                            {assessment.project_name}
                          </span>
                          <span className={styles.folderStatus}>
                            <StatusPill status={status} />
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
          onRefresh={refresh}
          assessments={assessments}
          reviewId={reviewId}
          loading={!health && !loadError}
        />
      )}
    </AppShell>
  );
}
