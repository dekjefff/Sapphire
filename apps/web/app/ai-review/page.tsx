import { WorkspacePage } from '@/components/workspace-page';

export const dynamic = 'force-dynamic';

export default async function AiReviewPage({
  searchParams,
}: {
  searchParams: Promise<{ assessment?: string | string[] }>;
}) {
  const { assessment } = await searchParams;
  return (
    <WorkspacePage
      section="review"
      reviewId={typeof assessment === 'string' ? assessment : undefined}
    />
  );
}
