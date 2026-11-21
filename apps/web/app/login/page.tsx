import { AuthError } from 'next-auth';
import { redirect } from 'next/navigation';
import { authenticationConfigured, readOperatorSession, signIn } from '@/auth';
import { canRegisterAccount } from '@/lib/local-accounts';
import { AccountLayout, Field } from './account-layout';
import styles from './page.module.css';

export const dynamic = 'force-dynamic';

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; registered?: string }>;
}) {
  if ((await readOperatorSession())?.user) redirect('/');

  const configured = authenticationConfigured();
  const { error, registered } = await searchParams;

  return (
    <AccountLayout title="Sign in to your account">
      {!configured ? (
        <p role="alert">Sign-in is unavailable. Contact your Sapphire administrator.</p>
      ) : (
        <>
          {registered && <p role="status">Account created. Sign in to continue.</p>}
          {error && (
            <p className={styles.error} role="alert">
              {error === 'CredentialsSignin'
                ? 'Email or password is incorrect. If you tried several times, wait a minute.'
                : 'Sign-in is unavailable right now. Try again shortly.'}
            </p>
          )}
          <form className={styles.form} action={login}>
            <Field
              name="email"
              label="Email"
              type="email"
              autoComplete="username"
              maxLength={254}
              placeholder="name@example.com"
            />
            <Field
              name="password"
              label="Password"
              type="password"
              autoComplete="current-password"
              maxLength={128}
            />
            <button className={styles.button} type="submit">
              Sign in
            </button>
          </form>
          {canRegisterAccount() && (
            <p>
              New user? <a href="/register">Register</a>
            </p>
          )}
        </>
      )}
    </AccountLayout>
  );
}

async function login(form: FormData) {
  'use server';

  if (!authenticationConfigured()) redirect('/login?error=Configuration');
  try {
    await signIn('credentials', {
      email: form.get('email'),
      password: form.get('password'),
      redirectTo: '/',
    });
  } catch (error) {
    if (error instanceof AuthError) {
      redirect(
        error.type === 'CredentialsSignin'
          ? '/login?error=CredentialsSignin'
          : '/login?error=Configuration',
      );
    }
    throw error;
  }
}
