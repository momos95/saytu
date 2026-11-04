import { AppRole, TokenSet, base64UrlEncode } from '../core/auth/oidc';

/** Unsigned JWT for tests (the SPA never verifies access-token signatures; the API does). */
export function fakeJwt(payload: object): string {
  const enc = (o: object) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));
  return `${enc({ alg: 'none' })}.${enc(payload)}.x`;
}

export function fakeTokens(roles: AppRole[], name = 'Awa Diop', expiresInMs = 300_000): TokenSet {
  return {
    accessToken: fakeJwt({ sub: 'u1', preferred_username: 'awa', name, realm_access: { roles } }),
    refreshToken: 'refresh-token',
    idToken: fakeJwt({ sub: 'u1', name }),
    expiresAt: Date.now() + expiresInMs,
    refreshExpiresAt: Date.now() + 1_800_000,
  };
}
