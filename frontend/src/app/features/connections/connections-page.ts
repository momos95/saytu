import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';
import { ConnectionForm } from './connection-form';
import { ConnectionTestResult } from './connection-test-result';
import { ConnectionsApi, errorMessage } from './connections.api';
import { ConnectionTest, GitConnection, providerInfo, statusLabel } from './connections.model';

/** Page 3 of the specification: Git connections. Editing is reserved to ADMIN (enforced by the API). */
@Component({
  selector: 'saytu-connections-page',
  imports: [DatePipe, ConnectionForm, ConnectionTestResult],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="page-header">
      <h1>Connexions Git</h1>
      @if (isAdmin() && !editing()) {
        <button type="button" class="primary" (click)="startCreate()">Nouvelle connexion</button>
      }
    </header>

    @if (editing()) {
      <saytu-connection-form [existing]="editTarget()" (saved)="onSaved()" (cancelled)="closeForm()" />
    }

    @if (error()) {
      <p class="error" role="alert">{{ error() }}</p>
    }

    @if (loading()) {
      <p class="muted">Chargement…</p>
    } @else if (connections().length === 0) {
      <section class="card empty">
        <p>Aucune connexion enregistrée.</p>
        <p class="muted">
          {{ isAdmin() ? 'Ajoutez une instance GitLab, GitHub, Bitbucket ou un répertoire local pour commencer.'
                       : 'Un administrateur doit enregistrer une connexion.' }}
        </p>
      </section>
    } @else {
      <ul class="list">
        @for (c of connections(); track c.id) {
          <li class="card" data-testid="connection">
            <div class="row">
              <div class="title">
                <strong>{{ c.name }}</strong>
                <span class="badge">{{ providerLabel(c) }}</span>
                @if (!c.enabled) {
                  <span class="badge off">Désactivée</span>
                }
              </div>
              <span class="status" [class.ok]="c.lastTest?.status === 'OK'"
                    [class.ko]="c.lastTest && c.lastTest.status !== 'OK'">{{ statusLabel(c.lastTest?.status) }}</span>
            </div>
            <div class="meta muted">
              <span>{{ c.baseUrl }}</span>
              <span>{{ c.hasToken ? 'Token enregistré (chiffré)' : (c.providerType === 'LOCAL' ? 'Sans token' : 'Accès anonyme') }}</span>
              @if (c.lastTest?.authenticatedAs) {
                <span>Compte : {{ c.lastTest?.authenticatedAs }}</span>
              }
              @if (c.lastTest) {
                <span>Testée le {{ c.lastTest.testedAt | date: 'short' }}</span>
              }
            </div>
            @if (expiresSoon(c)) {
              <p class="warning">Le token expire le {{ c.tokenExpiresAt | date: 'longDate' }}.</p>
            }
            @if (c.lastTest?.message) {
              <p class="error">{{ c.lastTest?.message }}</p>
            }
            @if (results()[c.id]; as r) {
              <saytu-connection-test-result [result]="r" />
            }
            @if (isAdmin()) {
              <div class="actions">
                <button type="button" (click)="test(c)" [disabled]="busyId() === c.id">
                  {{ busyId() === c.id ? 'Test…' : 'Tester' }}
                </button>
                <button type="button" (click)="startEdit(c)">Modifier</button>
                @if (confirmDeleteId() === c.id) {
                  <span class="confirm">Supprimer aussi ses dépôts et résultats ?</span>
                  <button type="button" class="danger" (click)="remove(c)">Confirmer</button>
                  <button type="button" (click)="confirmDeleteId.set(null)">Annuler</button>
                } @else {
                  <button type="button" (click)="confirmDeleteId.set(c.id)">Supprimer</button>
                }
              </div>
            }
          </li>
        }
      </ul>
    }
  `,
  styles: `
    .page-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
    h1 { margin: 0; font-size: 1.5rem; }
    .list { list-style: none; margin: 16px 0 0; padding: 0; display: flex; flex-direction: column; gap: 12px; }
    .row { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; align-items: center; }
    .title { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .badge { font-size: .75rem; padding: .1rem .5rem; border-radius: 999px; background: var(--saytu-hover); }
    .badge.off { color: var(--saytu-muted); }
    .status { font-size: .85rem; font-weight: 600; color: var(--saytu-muted); }
    .status.ok { color: var(--saytu-accent); }
    .status.ko { color: var(--saytu-critical); }
    .meta { display: flex; flex-wrap: wrap; gap: 4px 16px; font-size: .85rem; margin-top: 6px; overflow-wrap: anywhere; }
    .warning { color: var(--saytu-medium); margin: 8px 0 0; font-size: .9rem; }
    .error { color: var(--saytu-critical); margin: 8px 0 0; font-size: .9rem; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; align-items: center; }
    .confirm { font-size: .85rem; }
    saytu-connection-test-result { display: block; margin-top: 10px; }
    saytu-connection-form { display: block; margin-bottom: 16px; }
    button { font: inherit; padding: .45rem .85rem; border-radius: 6px; border: 1px solid var(--saytu-border);
             background: var(--saytu-surface); color: var(--saytu-text); cursor: pointer; }
    button.primary { background: var(--saytu-accent); border-color: var(--saytu-accent); color: #fff; }
    button.danger { border-color: var(--saytu-critical); color: var(--saytu-critical); }
    button:disabled { opacity: .6; }
  `,
})
export class ConnectionsPage implements OnInit {
  private readonly api = inject(ConnectionsApi);
  private readonly auth = inject(AuthService);

  readonly connections = signal<GitConnection[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly editing = signal(false);
  readonly editTarget = signal<GitConnection | undefined>(undefined);
  readonly busyId = signal<string | null>(null);
  readonly confirmDeleteId = signal<string | null>(null);
  readonly results = signal<Record<string, ConnectionTest>>({});
  readonly isAdmin = computed(() => this.auth.hasRole('ADMIN'));
  readonly statusLabel = statusLabel;

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.loading.set(true);
    this.api.list().subscribe({
      next: list => {
        this.connections.set(list);
        this.loading.set(false);
      },
      error: e => {
        this.error.set(errorMessage(e));
        this.loading.set(false);
      },
    });
  }

  providerLabel(c: GitConnection): string {
    return providerInfo(c.providerType).label;
  }

  expiresSoon(c: GitConnection): boolean {
    if (!c.tokenExpiresAt) {
      return false;
    }
    return new Date(c.tokenExpiresAt).getTime() - Date.now() < 14 * 24 * 3600 * 1000;
  }

  startCreate(): void {
    this.editTarget.set(undefined);
    this.editing.set(true);
  }

  startEdit(c: GitConnection): void {
    this.editTarget.set(c);
    this.editing.set(true);
  }

  closeForm(): void {
    this.editing.set(false);
    this.editTarget.set(undefined);
  }

  onSaved(): void {
    this.closeForm();
    this.reload();
  }

  test(c: GitConnection): void {
    this.busyId.set(c.id);
    this.api.test(c.id).subscribe({
      next: r => {
        this.results.update(all => ({ ...all, [c.id]: r }));
        this.busyId.set(null);
        this.reload();
      },
      error: e => {
        this.error.set(errorMessage(e));
        this.busyId.set(null);
      },
    });
  }

  remove(c: GitConnection): void {
    this.api.delete(c.id).subscribe({
      next: () => {
        this.confirmDeleteId.set(null);
        this.reload();
      },
      error: e => this.error.set(errorMessage(e)),
    });
  }
}
