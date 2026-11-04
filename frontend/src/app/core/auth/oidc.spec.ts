import {
  OidcError,
  OidcSettings,
  PENDING_MAX_AGE_MS,
  base64UrlDecode,
  base64UrlEncode,
  canRefresh,
  checkPending,
  createAuthorizationRequest,
  decodeJwt,
  exchangeCode,
  logoutUrl,
  needsRefresh,
  parseCallback,
  pkceChallenge,
  rolesOf,
  safeReturnUrl,
  toTokenSet,
  validateIdToken,
} from './oidc';

const settings: OidcSettings = {
  issuer: 'https://sso.example.org/realms/africodeshield',
  clientId: 'africodeshield-web',
  redirectUri: 'https://audit.example.org/auth/callback',
};

function jwt(payload: object): string {
  const enc = (o: object) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));
  return `${enc({ alg: 'RS256' })}.${enc(payload)}.signature`;
}

function jsonResponse(status: number, body: object): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

async function rejection(promise: Promise<unknown>): Promise<OidcError> {
  try {
    await promise;
  } catch (e) {
    return e as OidcError;
  }
  throw new Error('expected rejection');
}

function thrown(fn: () => unknown): OidcError {
  try {
    fn();
  } catch (e) {
    return e as OidcError;
  }
  throw new Error('expected an exception');
}

describe('oidc', () => {
  it('computes the RFC 7636 appendix B PKCE challenge', async () => {
    expect(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });

  it('round-trips base64url including non-ASCII', () => {
    const encoded = base64UrlEncode(new TextEncoder().encode('Awa Diop — é✓'));
    expect(encoded).not.toMatch(/[+/=]/);
    expect(base64UrlDecode(encoded)).toBe('Awa Diop — é✓');
  });

  it('builds an authorization request with PKCE, state and nonce', async () => {
    const { url, pending } = await createAuthorizationRequest(settings, '/connections', 1000);
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe('https://sso.example.org/realms/africodeshield/protocol/openid-connect/auth');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('code_challenge')).toBe(await pkceChallenge(pending.verifier));
    expect(u.searchParams.get('state')).toBe(pending.state);
    expect(u.searchParams.get('nonce')).toBe(pending.nonce);
    expect(u.searchParams.get('response_type')).toBe('code');
    expect(u.searchParams.get('scope')).toBe('openid profile email');
    expect(pending.state.length).toBeGreaterThanOrEqual(43);
    expect(pending.verifier.length).toBeGreaterThanOrEqual(43);
    expect(pending.returnUrl).toBe('/connections');
    expect(url).not.toContain(pending.verifier);
  });

  it('never returns to another site', () => {
    expect(safeReturnUrl('/findings?severity=HIGH')).toBe('/findings?severity=HIGH');
    for (const bad of ['https://evil.example', '//evil.example', '/\\evil.example', 'javascript:alert(1)', '', null,
      '/auth/callback?code=x']) {
      expect(safeReturnUrl(bad)).toBe('/');
    }
  });

  it('parses callbacks', () => {
    expect(parseCallback('?code=abc&state=xyz&session_state=1')).toEqual({ code: 'abc', state: 'xyz' });
    expect(parseCallback('?error=access_denied&error_description=Denied&state=s')).toEqual({
      error: 'access_denied',
      description: 'Denied',
      state: 's',
    });
    expect(parseCallback('?foo=bar')).toBeNull();
  });

  it('checks state and age of the pending login', () => {
    const pending = { state: 's', nonce: 'n', verifier: 'v', returnUrl: '/', createdAt: 0 };
    expect(checkPending(pending, 's', 1000)).toBe(pending);
    expect(thrown(() => checkPending(pending, 'other', 1000)).code).toBe('state_mismatch');
    expect(thrown(() => checkPending(null, 's')).code).toBe('no_pending_login');
    expect(thrown(() => checkPending(pending, 's', PENDING_MAX_AGE_MS + 1)).code).toBe('login_expired');
  });

  it('exchanges the code with the verifier', async () => {
    let sentBody = '';
    const fetchFn = async (_url: string, init?: RequestInit) => {
      sentBody = String(init?.body);
      return jsonResponse(200, { access_token: 'at', expires_in: 300, refresh_token: 'rt', refresh_expires_in: 1800, id_token: 'it' });
    };
    const tokens = await exchangeCode(fetchFn, settings, 'the-code', 'the-verifier', 1_000);
    expect(tokens).toEqual({ accessToken: 'at', refreshToken: 'rt', idToken: 'it', expiresAt: 301_000, refreshExpiresAt: 1_801_000 });
    const body = new URLSearchParams(sentBody);
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code_verifier')).toBe('the-verifier');
    expect(body.get('client_id')).toBe('africodeshield-web');
  });

  it('reports token endpoint errors and network failures', async () => {
    const refused = await rejection(
      exchangeCode(async () => jsonResponse(400, { error: 'invalid_grant', error_description: 'Code not valid' }), settings, 'c', 'v'),
    );
    expect(refused.code).toBe('invalid_grant');
    expect(refused.message).toBe('Code not valid');
    const offline = await rejection(exchangeCode(async () => { throw new TypeError('Failed to fetch'); }, settings, 'c', 'v'));
    expect(offline.code).toBe('network_error');
    expect(thrown(() => toTokenSet({ token_type: 'Bearer' })).code).toBe('invalid_token_response');
  });

  it('decodes and validates the ID token', () => {
    const now = 1_700_000_000_000;
    const good = { iss: settings.issuer, aud: 'africodeshield-web', nonce: 'n1', exp: now / 1000 + 300 };
    expect(() => validateIdToken(decodeJwt(jwt(good)), { ...settings, nonce: 'n1' }, now)).not.toThrow();
    const expectCode = (claims: object, code: string) =>
      expect(thrown(() => validateIdToken(decodeJwt(jwt(claims)), { ...settings, nonce: 'n1' }, now)).code).toBe(code);
    expectCode({ ...good, iss: 'https://evil' }, 'invalid_issuer');
    expectCode({ ...good, aud: 'other' }, 'invalid_audience');
    expectCode({ ...good, aud: ['other', 'africodeshield-web'], azp: 'other' }, 'invalid_azp');
    expectCode({ ...good, nonce: 'replayed' }, 'invalid_nonce');
    expectCode({ ...good, exp: now / 1000 - 3600 }, 'token_expired');
    expect(thrown(() => decodeJwt('not-a-jwt')).code).toBe('invalid_jwt');
    expect(thrown(() => decodeJwt('a.bm90IGpzb24.c')).code).toBe('invalid_jwt');
  });

  it('keeps application roles only', () => {
    expect(rolesOf({ realm_access: { roles: ['offline_access', 'VIEWER', 'ADMIN', 'uma_authorization'] } })).toEqual(['ADMIN', 'VIEWER']);
    expect(rolesOf(null)).toEqual([]);
  });

  it('decides when to refresh', () => {
    const t = { accessToken: 'a', refreshToken: 'r', expiresAt: 100_000, refreshExpiresAt: 200_000 };
    expect(needsRefresh(t, 10_000)).toBeFalse();
    expect(needsRefresh(t, 75_000)).toBeTrue();
    expect(canRefresh(t, 150_000)).toBeTrue();
    expect(canRefresh(t, 250_000)).toBeFalse();
    expect(canRefresh({ ...t, refreshToken: undefined }, 0)).toBeFalse();
  });

  it('builds the logout URL', () => {
    const u = new URL(logoutUrl(settings, 'id.tok.en', 'https://audit.example.org/login?loggedOut=1'));
    expect(u.pathname).toBe('/realms/africodeshield/protocol/openid-connect/logout');
    expect(u.searchParams.get('id_token_hint')).toBe('id.tok.en');
    expect(u.searchParams.get('post_logout_redirect_uri')).toBe('https://audit.example.org/login?loggedOut=1');
  });
});
