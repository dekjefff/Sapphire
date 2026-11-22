import { redirect } from 'next/navigation';
import { authenticationConfigured, readOperatorSession } from '@/auth';
import { canRegisterAccount, registerAccount } from '@/lib/local-accounts';
import { AccountLayout, Field } from '../login/account-layout';
import styles from '../login/page.module.css';

export const dynamic = 'force-dynamic';

export default async function RegisterPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  if ((await readOperatorSession())?.user) redirect('/');
  const available = authenticationConfigured() && canRegisterAccount();
  const { error } = await searchParams;

  return (
    <AccountLayout title="Create your account">
      {available ? (
        <>
          {error && (
            <p className={styles.error} role="alert">
              {error === 'fields'
                ? 'Enter valid account details and matching passwords of at least 12 characters.'
                : 'Registration could not be completed. Check your setup code and email.'}
            </p>
          )}
          <form className={styles.form} action={register}>
            <Field name="firstName" label="First name" autoComplete="given-name" maxLength={80} />
            <Field name="lastName" label="Last name" autoComplete="family-name" maxLength={80} />
            <Field
              name="email"
              label="Email"
              type="email"
              autoComplete="email"
              maxLength={254}
              placeholder="name@example.com"
            />
            <Field
              name="password"
              label="Password"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
            />
            <Field
              name="confirmPassword"
              label="Confirm password"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
            />
            <Field
              name="setupCode"
              label="Setup code"
              type="password"
              autoComplete="off"
              maxLength={128}
            />
            <button className={styles.button} type="submit">
              Register
            </button>
          </form>
        </>
      ) : (
        <p>Registration is closed. Ask your Sapphire administrator for a setup code.</p>
      )}
      <p>
        Already registered? <a href="/login">Sign in</a>
      </p>
    </AccountLayout>
  );
}

async function register(form: FormData) {
  'use server';

  if (!authenticationConfigured()) redirect('/login?error=Configuration');
  const result = await registerAccount(form);
  redirect(result === 'created' ? '/login?registered=1' : '/register?error=' + result);
}
