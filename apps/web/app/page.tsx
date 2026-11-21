import { WorkspacePage } from '@/components/workspace-page';

export const dynamic = 'force-dynamic';

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<{ section?: string }>;
}) {
  const { section } = await searchParams;
  return <WorkspacePage section={section === 'new' ? 'new' : 'recent'} />;
}
