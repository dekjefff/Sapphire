import { redirect } from 'next/navigation';
import { readOperatorSession, signOut } from '@/auth';
import { Dashboard } from '@/components/dashboard';

export async function WorkspacePage({
  section,
  reviewId,
}: {
  section?: 'recent' | 'new' | 'review';
  reviewId?: string;
}) {
  const session = await readOperatorSession();
  if (!session?.user) redirect('/login');

  return (
    <Dashboard
      initialSection={section}
      reviewId={reviewId}
      reviewProvider="groq"
      account={
        <form
          className="account-bar"
          action={async () => {
            'use server';
            await signOut({ redirect: false });
            const logout = new URL(
              process.env.AUTH_KEYCLOAK_ISSUER + '/protocol/openid-connect/logout',
            );
            logout.searchParams.set('client_id', process.env.AUTH_KEYCLOAK_ID!);
            logout.searchParams.set(
              'post_logout_redirect_uri',
              new URL('/login', process.env.AUTH_URL).href,
            );
            redirect(logout.href);
          }}
        >
          <button type="submit">Sign out</button>
        </form>
      }
    />
  );
}
