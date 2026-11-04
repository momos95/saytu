import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { ConnectionTest, statusLabel } from './connections.model';

/** Outcome of a connection test: status, identity, scopes, warnings. */
@Component({
  selector: 'acs-connection-test-result',
  imports: [DatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let r = result();
    <div class="result" [class.ok]="r.success" [class.ko]="!r.success" role="status" data-testid="test-result">
      <strong>{{ label(r.status) }}</strong>
      @if (r.message) {
        <p class="message">{{ r.message }}</p>
      }
      <dl>
        @if (r.authenticatedAs) {
          <dt>Compte</dt><dd>{{ r.authenticatedAs }}</dd>
        }
        @if (r.serverVersion) {
          <dt>Serveur</dt><dd>{{ r.serverVersion }}</dd>
        }
        @if (r.grantedScopes.length) {
          <dt>Scopes</dt><dd>{{ r.grantedScopes.join(', ') }}</dd>
        }
        @if (r.tokenExpiresAt) {
          <dt>Expiration du token</dt><dd>{{ r.tokenExpiresAt | date: 'longDate' }}</dd>
        }
      </dl>
      @if (r.warnings.length) {
        <ul class="warnings">
          @for (w of r.warnings; track w) {
            <li>{{ w }}</li>
          }
        </ul>
      }
    </div>
  `,
  styles: `
    .result { border-radius: 8px; padding: 12px 14px; border: 1px solid var(--acs-border); }
    .ok { border-color: var(--acs-accent); background: var(--acs-accent-soft); }
    .ko { border-color: var(--acs-critical); }
    .ko strong { color: var(--acs-critical); }
    .message { margin: .4rem 0 0; }
    dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .8rem; margin: .5rem 0 0; font-size: .9rem; }
    dt { color: var(--acs-muted); }
    dd { margin: 0; overflow-wrap: anywhere; }
    .warnings { margin: .5rem 0 0; padding-left: 1.1rem; color: var(--acs-medium); font-size: .9rem; }
  `,
})
export class ConnectionTestResult {
  readonly result = input.required<ConnectionTest>();
  readonly label = statusLabel;
}
