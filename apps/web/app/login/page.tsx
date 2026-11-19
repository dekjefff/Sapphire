import { redirect } from 'next/navigation';
import { authenticationConfigured, readOperatorSession, signIn } from '@/auth';
import styles from './page.module.css';

export const dynamic = 'force-dynamic';

type Props = { searchParams: Promise<{ error?: string }> };

export default async function LoginPage({ searchParams }: Props) {
  if ((await readOperatorSession())?.user) redirect('/');
  const configured = authenticationConfigured();
  const { error } = await searchParams;

  return (
    <main className={styles.page}>
      <section className={styles.panel} aria-labelledby="login-title">
        <p className={styles.brand}>Sapphire</p>
        <h1 id="login-title">Sign in</h1>
        {configured ? (
          <p>Sign in with your Sapphire account to access assessments.</p>
        ) : (
          <p className={styles.notice} role="alert">
            Sign-in is unavailable. Contact your Sapphire administrator to configure the account
            provider.
          </p>
        )}
        {configured && error && (
          <p className={styles.notice} role="alert">
            {error === 'AccessDenied'
              ? 'Your account needs operator access. Contact your Sapphire administrator.'
              : 'Sign-in could not be completed. Try again.'}
          </p>
        )}
        {configured && (
          <>
            <form
              action={async () => {
                'use server';
                if (!authenticationConfigured()) redirect('/login');
                await signIn('keycloak', { redirectTo: '/' }, { prompt: 'login' });
              }}
            >
              <button className={styles.button} type="submit">
                Sign in or register
              </button>
            </form>
            <p className={styles.note}>
              New accounts need administrator approval to access assessments.
            </p>
          </>
        )}
      </section>
    </main>
  );
}
