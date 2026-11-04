import { DOCUMENT } from '@angular/common';
import { Injectable, InjectionToken, computed, inject, signal } from '@angular/core';
import { AppConfigService } from '../config/app-config';
import {
  AppRole,
  Claims,
  FetchFn,
  OidcError,
  OidcSettings,
  PendingLogin,
  TokenSet,
  canRefresh,
  checkPending,
  createAuthorizationRequest,
  decodeJwt,
  exchangeCode,
  logoutUrl,
  needsRefresh,
  parseCallback,
  refreshTokens,
  rolesOf,
  validateIdToken,
} from './oidc';

/** fetch used for the token endpoint; replaced in tests. */
export const OIDC_FETCH = new InjectionToken<FetchFn>('OIDC_FETCH', {
  providedIn: 'root',
  factory: () => (input: string, init?: RequestInit) => fetch(input, init),
});

export const CALLBACK_PATH = '/auth/callback';
const PENDING_KEY = 'acs.oidc.pending';

/**
 * Session of the signed-in user. Tokens are kept in memory only: a page reload goes back through
 * Keycloak, which answers immediately while its SSO session is alive.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly config = inject(AppConfigService);
  private readonly document = inject(DOCUMENT);
  private readonly fetchFn = inject(OIDC_FETCH);

  private readonly tokens = signal<TokenSet | null>(null);
  private refreshing: Promise<TokenSet | null> | null = null;

  readonly isAuthenticated = computed(() => this.tokens() !== null);
  /** Claims of the access token (roles) merged with the ID token (profile). */
  readonly claims = computed<Claims | null>(() => {
    const t = this.tokens();
    if (!t) {
      return null;
    }
    const access = safeDecode(t.accessToken);
    const id = t.idToken ? safeDecode(t.idToken) : null;
    return { ...(id ?? {}), ...(access ?? {}) };
  });
  readonly roles = computed<AppRole[]>(() => rolesOf(this.claims()));
  readonly displayName = computed(() => {
    const c = this.claims();
    return c?.name || c?.preferred_username || c?.email || '';
  });

  hasRole(role: AppRole): boolean {
    return this.roles().includes(role);
  }

  settings(): OidcSettings {
    const cfg = this.config.config();
    return { issuer: cfg.oidcIssuer, clientId: cfg.oidcClientId, redirectUri: this.origin() + CALLBACK_PATH };
  }

  /**
   * Called once at start-up. On the callback URL, completes the login and rewrites the address bar
   * to the page the user wanted (or to /login with an error) before the router starts.
   */
  async init(): Promise<void> {
    const location = this.document.location;
    if (location.pathname !== CALLBACK_PATH) {
      return;
    }
    const pending = this.takePending();
    const params = parseCallback(location.search);
    try {
      if (!params) {
        throw new OidcError('Invalid login response.', 'invalid_callback');
      }
      if ('error' in params) {
        throw new OidcError(params.description || 'Login refused by the identity server.', params.error);
      }
      const checked = checkPending(pending, params.state);
      const settings = this.settings();
      const tokens = await exchangeCode(this.fetchFn, settings, params.code, checked.verifier);
      if (!tokens.idToken) {
        throw new OidcError('No ID token received.', 'missing_id_token');
      }
      validateIdToken(decodeJwt(tokens.idToken), { issuer: settings.issuer, clientId: settings.clientId, nonce: checked.nonce });
      this.tokens.set(tokens);
      this.replaceUrl(checked.returnUrl);
    } catch (e) {
      const code = e instanceof OidcError ? e.code : 'login_failed';
      this.replaceUrl(`/login?error=${encodeURIComponent(code)}`);
    }
  }

  /** Redirects the browser to Keycloak. */
  async login(returnUrl = '/'): Promise<void> {
    const { url, pending } = await createAuthorizationRequest(this.settings(), returnUrl);
    try {
      this.document.defaultView?.sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
    } catch {
      // storage disabled: the callback will report "no login in progress"
    }
    this.document.location.assign(url);
  }

  /** Ends the local and the Keycloak session. */
  logout(): void {
    const idToken = this.tokens()?.idToken;
    this.tokens.set(null);
    this.document.location.assign(logoutUrl(this.settings(), idToken, this.origin() + '/login?loggedOut=1'));
  }

  /** Current access token, refreshed when close to expiry; null when the session is over. */
  async accessToken(): Promise<string | null> {
    const t = this.tokens();
    if (!t) {
      return null;
    }
    if (!needsRefresh(t)) {
      return t.accessToken;
    }
    if (!canRefresh(t)) {
      this.tokens.set(null);
      return null;
    }
    this.refreshing ??= refreshTokens(this.fetchFn, this.settings(), t.refreshToken!)
      .then(fresh => {
        // Keycloak may omit the ID token on refresh: keep the previous one for logout.
        const merged = { ...fresh, idToken: fresh.idToken ?? t.idToken };
        this.tokens.set(merged);
        return merged;
      })
      .catch(() => {
        this.tokens.set(null);
        return null;
      })
      .finally(() => (this.refreshing = null));
    return (await this.refreshing)?.accessToken ?? null;
  }

  /** Session lost (401 from the API): forget tokens so that the guard sends the user to Keycloak. */
  invalidate(): void {
    this.tokens.set(null);
  }

  /** Test hook. */
  setTokensForTesting(tokens: TokenSet | null): void {
    this.tokens.set(tokens);
  }

  private takePending(): PendingLogin | null {
    const storage = this.document.defaultView?.sessionStorage;
    try {
      const raw = storage?.getItem(PENDING_KEY);
      storage?.removeItem(PENDING_KEY);
      return raw ? (JSON.parse(raw) as PendingLogin) : null;
    } catch {
      return null;
    }
  }

  private replaceUrl(url: string): void {
    this.document.defaultView?.history.replaceState(null, '', url);
  }

  private origin(): string {
    return this.document.location.origin;
  }
}

function safeDecode(token: string): Claims | null {
  try {
    return decodeJwt(token);
  } catch {
    return null;
  }
}
