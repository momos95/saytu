/**
 * OpenID Connect authorization code flow with PKCE (RFC 7636) for a public SPA client, written
 * against Keycloak. Framework-free on purpose: no Angular import, so it is unit-testable in plain
 * Node and auditable on its own (see docs/adr/0006-oidc-spa.md).
 *
 * Security choices:
 * - PKCE S256, random `state` (CSRF) and `nonce` (ID token replay), 32 random bytes each;
 * - tokens live in memory only; only the short-lived PKCE verifier/state/nonce touch sessionStorage
 *   during the redirect;
 * - ID token claims (iss, aud, azp, nonce, exp) are validated; its signature is not, which OIDC
 *   Core §3.1.3.7 allows when the token is received directly from the token endpoint over TLS.
 */

export const APP_ROLES = ['ADMIN', 'AUDITOR', 'VIEWER'] as const;
export type AppRole = (typeof APP_ROLES)[number];

export interface OidcSettings {
  /** e.g. https://sso.example.org/realms/africodeshield (no trailing slash) */
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
}

export interface PendingLogin {
  state: string;
  nonce: string;
  verifier: string;
  returnUrl: string;
  createdAt: number;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  /** epoch ms */
  expiresAt: number;
  /** epoch ms, undefined when the server did not say */
  refreshExpiresAt?: number;
}

export interface Claims {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  azp?: string;
  exp?: number;
  nonce?: string;
  preferred_username?: string;
  name?: string;
  email?: string;
  realm_access?: { roles?: string[] };
  [key: string]: unknown;
}

export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export class OidcError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = 'OidcError';
  }
}

/** A pending login older than this is rejected (abandoned tab, replayed URL). */
export const PENDING_MAX_AGE_MS = 10 * 60 * 1000;
/** Tokens are refreshed when they expire within this margin. */
export const REFRESH_SKEW_MS = 30 * 1000;

export function endpoints(issuer: string) {
  const base = issuer.replace(/\/+$/, '') + '/protocol/openid-connect';
  return { authorization: `${base}/auth`, token: `${base}/token`, endSession: `${base}/logout` };
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(value: string): string {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function randomString(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/** Only same-application relative paths are accepted as return URLs (no open redirect). */
export function safeReturnUrl(url: string | null | undefined): string {
  if (!url || !url.startsWith('/') || url.startsWith('//') || url.startsWith('/\\') || url.startsWith('/auth/callback')) {
    return '/';
  }
  return url;
}

export async function createAuthorizationRequest(
  settings: OidcSettings,
  returnUrl: string,
  now = Date.now(),
): Promise<{ url: string; pending: PendingLogin }> {
  const pending: PendingLogin = {
    state: randomString(),
    nonce: randomString(),
    verifier: randomString(48),
    returnUrl: safeReturnUrl(returnUrl),
    createdAt: now,
  };
  const params = new URLSearchParams({
    client_id: settings.clientId,
    redirect_uri: settings.redirectUri,
    response_type: 'code',
    response_mode: 'query',
    scope: settings.scope ?? 'openid profile email',
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: await pkceChallenge(pending.verifier),
    code_challenge_method: 'S256',
  });
  return { url: `${endpoints(settings.issuer).authorization}?${params.toString()}`, pending };
}

export type CallbackParams = { code: string; state: string } | { error: string; description: string; state?: string };

/** Reads `?code=...&state=...` or `?error=...` from a location search string. */
export function parseCallback(search: string): CallbackParams | null {
  const params = new URLSearchParams(search);
  const error = params.get('error');
  if (error) {
    return { error, description: params.get('error_description') ?? '', state: params.get('state') ?? undefined };
  }
  const code = params.get('code');
  const state = params.get('state');
  return code && state ? { code, state } : null;
}

export function checkPending(pending: PendingLogin | null, state: string, now = Date.now()): PendingLogin {
  if (!pending) {
    throw new OidcError('No login in progress in this tab.', 'no_pending_login');
  }
  if (pending.state !== state) {
    throw new OidcError('The login response does not match the request (state).', 'state_mismatch');
  }
  if (now - pending.createdAt > PENDING_MAX_AGE_MS) {
    throw new OidcError('The login took too long, please try again.', 'login_expired');
  }
  return pending;
}

async function tokenRequest(fetchFn: FetchFn, settings: OidcSettings, body: URLSearchParams, now: number): Promise<TokenSet> {
  let response: Response;
  try {
    response = await fetchFn(endpoints(settings.issuer).token, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      credentials: 'omit',
    });
  } catch {
    throw new OidcError('The identity server cannot be reached.', 'network_error');
  }
  let json: Record<string, unknown> = {};
  try {
    json = (await response.json()) as Record<string, unknown>;
  } catch {
    // keep empty
  }
  if (!response.ok) {
    const code = typeof json['error'] === 'string' ? (json['error'] as string) : `http_${response.status}`;
    throw new OidcError(
      typeof json['error_description'] === 'string' ? (json['error_description'] as string) : 'Token request refused.',
      code,
    );
  }
  return toTokenSet(json, now);
}

export function toTokenSet(json: Record<string, unknown>, now = Date.now()): TokenSet {
  const accessToken = json['access_token'];
  const expiresIn = Number(json['expires_in']);
  if (typeof accessToken !== 'string' || !Number.isFinite(expiresIn)) {
    throw new OidcError('Malformed token response.', 'invalid_token_response');
  }
  const refreshIn = Number(json['refresh_expires_in']);
  return {
    accessToken,
    refreshToken: typeof json['refresh_token'] === 'string' ? (json['refresh_token'] as string) : undefined,
    idToken: typeof json['id_token'] === 'string' ? (json['id_token'] as string) : undefined,
    expiresAt: now + expiresIn * 1000,
    // Keycloak sends 0 for offline tokens (no expiry)
    refreshExpiresAt: Number.isFinite(refreshIn) && refreshIn > 0 ? now + refreshIn * 1000 : undefined,
  };
}

export function exchangeCode(fetchFn: FetchFn, settings: OidcSettings, code: string, verifier: string, now = Date.now()) {
  return tokenRequest(
    fetchFn,
    settings,
    new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: settings.clientId,
      redirect_uri: settings.redirectUri,
      code,
      code_verifier: verifier,
    }),
    now,
  );
}

export function refreshTokens(fetchFn: FetchFn, settings: OidcSettings, refreshToken: string, now = Date.now()) {
  return tokenRequest(
    fetchFn,
    settings,
    new URLSearchParams({ grant_type: 'refresh_token', client_id: settings.clientId, refresh_token: refreshToken }),
    now,
  );
}

/** Decodes a JWT payload. Does NOT verify the signature (the API does, for access tokens). */
export function decodeJwt(token: string): Claims {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new OidcError('Malformed token.', 'invalid_jwt');
  }
  try {
    const claims = JSON.parse(base64UrlDecode(parts[1])) as unknown;
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      throw new Error('not an object');
    }
    return claims as Claims;
  } catch {
    throw new OidcError('Malformed token.', 'invalid_jwt');
  }
}

export function validateIdToken(
  claims: Claims,
  expected: { issuer: string; clientId: string; nonce: string },
  now = Date.now(),
): void {
  if (claims.iss !== expected.issuer) {
    throw new OidcError('ID token issued by an unexpected server.', 'invalid_issuer');
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(expected.clientId)) {
    throw new OidcError('ID token not issued for this application.', 'invalid_audience');
  }
  if (audiences.length > 1 && claims.azp !== expected.clientId) {
    throw new OidcError('ID token authorized party mismatch.', 'invalid_azp');
  }
  if (claims.nonce !== expected.nonce) {
    throw new OidcError('ID token replay detected (nonce).', 'invalid_nonce');
  }
  if (typeof claims.exp !== 'number' || claims.exp * 1000 < now - 60_000) {
    throw new OidcError('ID token expired.', 'token_expired');
  }
}

export function rolesOf(claims: Claims | null): AppRole[] {
  const roles = claims?.realm_access?.roles ?? [];
  return APP_ROLES.filter(r => roles.includes(r));
}

export function needsRefresh(tokens: TokenSet, now = Date.now()): boolean {
  return tokens.expiresAt - REFRESH_SKEW_MS <= now;
}

export function canRefresh(tokens: TokenSet, now = Date.now()): boolean {
  return !!tokens.refreshToken && (tokens.refreshExpiresAt === undefined || tokens.refreshExpiresAt > now);
}

export function logoutUrl(settings: OidcSettings, idToken: string | undefined, postLogoutRedirectUri: string): string {
  const params = new URLSearchParams({ client_id: settings.clientId, post_logout_redirect_uri: postLogoutRedirectUri });
  if (idToken) {
    params.set('id_token_hint', idToken);
  }
  return `${endpoints(settings.issuer).endSession}?${params.toString()}`;
}
