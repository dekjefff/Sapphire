import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { verifyAccount } from '@/lib/local-accounts';

export function authenticationConfigured() {
  const { AUTH_SECRET, AUTH_URL } = process.env;
  return Boolean(
    AUTH_SECRET &&
    AUTH_SECRET.length >= 32 &&
    AUTH_URL &&
    /^https?:\/\//.test(AUTH_URL) &&
    URL.canParse(AUTH_URL),
  );
}

export async function readOperatorSession() {
  return authenticationConfigured() ? auth() : null;
}

export const { auth, handlers, signIn, signOut } = NextAuth({
  providers: [
    Credentials({
      credentials: { email: { type: 'email' }, password: { type: 'password' } },
      authorize: ({ email, password }) =>
        authenticationConfigured() ? verifyAccount(email, password) : null,
    }),
  ],
  pages: { signIn: '/login', error: '/login' },
  session: { strategy: 'jwt', maxAge: 60 * 60 },
  callbacks: {
    jwt({ token, user }) {
      if (user) token.sapphireLocalAccount = true;
      return token.sapphireLocalAccount ? token : null;
    },
  },
});
