import { provideHttpClient } from '@angular/common/http';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { fakeTokens } from '../../testing/fake-session';
import { AuthService, OIDC_FETCH } from './auth.service';

describe('AuthService', () => {
  let calls: number;
  let respond: () => Promise<Response>;

  function setUp(): AuthService {
    calls = 0;
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        provideHttpClient(),
        { provide: OIDC_FETCH, useValue: () => { calls++; return respond(); } },
      ],
    });
    return TestBed.inject(AuthService);
  }

  const tokenResponse = () =>
    Promise.resolve(new Response(JSON.stringify({ access_token: 'fresh', expires_in: 300, refresh_token: 'r2' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }));

  it('exposes roles and name from the tokens', () => {
    const auth = setUp();
    auth.setTokensForTesting(fakeTokens(['AUDITOR', 'VIEWER']));
    expect(auth.isAuthenticated()).toBeTrue();
    expect(auth.roles()).toEqual(['AUDITOR', 'VIEWER']);
    expect(auth.hasRole('ADMIN')).toBeFalse();
    expect(auth.displayName()).toBe('Awa Diop');
  });

  it('returns a valid token without network calls', async () => {
    const auth = setUp();
    respond = tokenResponse;
    auth.setTokensForTesting(fakeTokens(['VIEWER']));
    expect(await auth.accessToken()).toContain('.');
    expect(calls).toBe(0);
  });

  it('refreshes an expiring token once for concurrent callers', async () => {
    const auth = setUp();
    respond = tokenResponse;
    auth.setTokensForTesting(fakeTokens(['VIEWER'], 'Awa', 1_000));
    const [a, b] = await Promise.all([auth.accessToken(), auth.accessToken()]);
    expect(a).toBe('fresh');
    expect(b).toBe('fresh');
    expect(calls).toBe(1);
  });

  it('ends the session when the refresh is refused', async () => {
    const auth = setUp();
    respond = () => Promise.resolve(new Response('{"error":"invalid_grant"}', { status: 400 }));
    auth.setTokensForTesting(fakeTokens(['VIEWER'], 'Awa', 1_000));
    expect(await auth.accessToken()).toBeNull();
    expect(auth.isAuthenticated()).toBeFalse();
  });
});
