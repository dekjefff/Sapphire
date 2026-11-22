import { createHash } from 'node:crypto';
import { redirect } from 'next/navigation';
import { readOperatorSession, signOut } from '@/auth';
import { Dashboard } from '@/components/dashboard';
import { AccountMenu } from './account-menu';

export async function WorkspacePage({
  section,
  reviewId,
}: {
  section?: 'overview' | 'recent' | 'new' | 'review' | 'url-checks';
  reviewId?: string;
}) {
  const session = await readOperatorSession();
  if (!session?.user) redirect('/login');
  const urlCheckScope = createHash('sha256')
    .update(session.user.email ?? session.user.name ?? 'local')
    .digest('hex');

  return (
    <Dashboard
      initialSection={section}
      urlCheckScope={urlCheckScope}
      reviewId={reviewId}
      account={
        <AccountMenu
          name={session.user.name?.trim() || session.user.email?.trim() || 'Sapphire account'}
          signOutAction={async () => {
            'use server';
            await signOut({ redirectTo: '/login' });
          }}
        />
      }
    />
  );
}
