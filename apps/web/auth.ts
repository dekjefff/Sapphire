import NextAuth, { customFetch } from 'next-auth';
import Keycloak from 'next-auth/providers/keycloak';

export function authenticationConfigured() {
  const { AUTH_SECRET, AUTH_URL, AUTH_KEYCLOAK_ID, AUTH_KEYCLOAK_SECRET, AUTH_KEYCLOAK_ISSUER } =
    process.env;
  return Boolean(
    AUTH_SECRET &&
    AUTH_URL &&
    URL.canParse(AUTH_URL) &&
    AUTH_KEYCLOAK_ID &&
    AUTH_KEYCLOAK_SECRET &&
    AUTH_KEYCLOAK_ISSUER &&
    URL.canParse(AUTH_KEYCLOAK_ISSUER),
  );
}

export async function readOperatorSession() {
  return authenticationConfigured() ? auth() : null;
}

export const { auth, handlers, signIn, signOut } = NextAuth(() => {
  const issuer = process.env.AUTH_KEYCLOAK_ISSUER;
  const internalOrigin = process.env.SAPPHIRE_IDENTITY_INTERNAL_ORIGIN;
  const providers = [
    Keycloak({
      issuer,
      checks: ['pkce', 'state', 'nonce'],
      [customFetch]: (input, init) => {
        const url = new URL(input instanceof Request ? input.url : input);
        if (!issuer || url.origin !== new URL(issuer).origin) {
          throw new Error('Identity endpoint origin is not allowed');
        }
        const endpoint = internalOrigin ? new URL(url.pathname + url.search, internalOrigin) : url;
        return fetch(endpoint, { ...init, redirect: 'error' });
      },
    }),
  ];

  return {
    providers,
    pages: { signIn: '/login', error: '/login' },
    session: { strategy: 'jwt', maxAge: 60 * 60 },
    callbacks: {
      signIn({ profile }) {
        const roles = profile?.sapphire_roles;
        return Array.isArray(roles) && roles.includes('operator');
      },
    },
  };
});
