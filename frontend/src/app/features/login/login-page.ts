import { ChangeDetectionStrategy, Component, computed, inject, input, signal } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';
import { safeReturnUrl } from '../../core/auth/oidc';

const ERROR_MESSAGES: Record<string, string> = {
  access_denied: 'La connexion a été refusée.',
  state_mismatch: 'La réponse de connexion ne correspond pas à la demande. Réessayez.',
  no_pending_login: 'Aucune connexion n’était en cours dans cet onglet. Réessayez.',
  login_expired: 'La connexion a pris trop de temps. Réessayez.',
  network_error: 'Le serveur d’identité est injoignable. Contactez l’administrateur.',
  invalid_grant: 'Le code de connexion a expiré ou a déjà été utilisé. Réessayez.',
  invalid_nonce: 'Réponse de connexion rejetée (rejeu détecté).',
  invalid_issuer: 'Réponse de connexion émise par un serveur inattendu.',
};

/**
 * Page 1 of the specification. The credentials form itself is Keycloak's (MFA, brute-force
 * protection, password policy); this page explains errors and starts the redirect.
 */
@Component({
  selector: 'acs-login-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="login">
      <section class="card">
        <div class="brand"><span class="logo" aria-hidden="true">◆</span> AfriCodeShield</div>
        <p class="muted">Audit de sécurité et de qualité du code, hébergé chez vous.</p>

        @if (loggedOut()) {
          <p class="notice" role="status">Vous êtes déconnecté.</p>
        }
        @if (errorMessage(); as message) {
          <p class="error" role="alert" data-testid="login-error">{{ message }}</p>
        }

        <button type="button" class="primary" (click)="signIn()" [disabled]="redirecting()">
          {{ redirecting() ? 'Redirection…' : 'Se connecter' }}
        </button>
        <p class="hint muted">Authentification via le serveur d’identité de votre organisation (Keycloak).</p>
      </section>
    </main>
  `,
  styles: `
    .login { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
    .card { width: 100%; max-width: 400px; display: flex; flex-direction: column; gap: 12px; }
    .brand { font-size: 1.4rem; font-weight: 700; display: flex; gap: .5rem; align-items: center; }
    .logo { color: var(--acs-accent); }
    .primary { padding: .7rem 1rem; border: 0; border-radius: 8px; background: var(--acs-accent); color: #fff;
               font-weight: 600; font-size: 1rem; cursor: pointer; }
    .primary:disabled { opacity: .7; cursor: progress; }
    .error { color: var(--acs-critical); margin: 0; }
    .notice { margin: 0; }
    .hint { font-size: .85rem; margin: 0; }
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);

  /** Query parameters bound by the router (withComponentInputBinding). */
  readonly error = input<string>();
  readonly returnUrl = input<string>();
  readonly loggedOutParam = input<string>(undefined, { alias: 'loggedOut' });

  readonly redirecting = signal(false);
  readonly loggedOut = computed(() => this.loggedOutParam() === '1');
  readonly errorMessage = computed(() => {
    const code = this.error();
    return code ? (ERROR_MESSAGES[code] ?? `La connexion a échoué (${code}).`) : null;
  });

  signIn(): void {
    this.redirecting.set(true);
    void this.auth.login(safeReturnUrl(this.returnUrl() ?? '/dashboard'));
  }
}
