import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { Observable } from 'rxjs';
import { AuthService } from '../../core/auth/auth.service';
import { ConnectionsApi, errorMessage } from '../connections/connections.api';
import { GitConnection } from '../connections/connections.model';
import { NamespaceRepositories } from './namespace-repositories';
import { SourcesApi } from './sources.api';
import { discoveryMessage, filterTree, orderTree } from './sources.logic';
import { KIND_LABELS, Namespace } from './sources.model';

/**
 * Page 4: organisations / groups / workspaces of each connection, and the repositories to audit.
 * Selecting a namespace with "tous les dépôts" includes its future repositories as well.
 */
@Component({
  selector: 'acs-repositories-page',
  imports: [DatePipe, NamespaceRepositories],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="page-header">
      <h1>Organisations et dépôts</h1>
    </header>

    @if (connections().length === 0 && !loading()) {
      <section class="card">
        <p>Aucune connexion Git. Commencez par en enregistrer une dans « Connexions Git ».</p>
      </section>
    } @else {
      <section class="card controls">
        <label>
          Connexion
          <select (change)="selectConnection($any($event.target).value)" [value]="connectionId() ?? ''">
            @for (c of connections(); track c.id) {
              <option [value]="c.id">{{ c.name }}{{ c.enabled ? '' : ' (désactivée)' }}</option>
            }
          </select>
        </label>
        @if (isAdmin()) {
          <button type="button" class="primary" (click)="discover()" [disabled]="busy() || !connectionId()">
            {{ busy() ? 'Synchronisation…' : 'Découvrir les organisations' }}
          </button>
        }
      </section>

      @if (message()) {
        <p class="message" role="status" data-testid="discovery-message">{{ message() }}</p>
      }
      @if (error()) {
        <p class="error" role="alert">{{ error() }}</p>
      }

      @if (isAdmin() && connectionId()) {
        <form class="add" (submit)="$event.preventDefault(); add(addInput.value); addInput.value = ''">
          <input #addInput placeholder="Ajouter par nom : organisation publique, workspace, groupe (ex. kubernetes)"
                 aria-label="Ajouter une organisation par son nom" maxlength="512" />
          <button type="submit" [disabled]="busy()">Ajouter</button>
        </form>
      }

      @if (namespaces().length > 0) {
        <input class="filter" type="search" placeholder="Filtrer les organisations…" (input)="filter.set($any($event.target).value)"
               aria-label="Filtrer les organisations" />
        <ul class="tree">
          @for (row of rows(); track row.namespace.id) {
            @let n = row.namespace;
            <li class="card" [style.margin-left.px]="row.depth * 20" [class.removed]="n.removed" data-testid="namespace">
              <div class="row">
                <div class="title">
                  <strong>{{ n.fullPath }}</strong>
                  <span class="badge">{{ kindLabel(n) }}</span>
                  @if (n.removed) { <span class="badge warn">n’existe plus sur la plateforme</span> }
                  @if (n.addedManually) { <span class="badge">ajouté par nom</span> }
                </div>
                <span class="muted counts">
                  {{ n.repositoryCount }} dépôt(s){{ n.includeAllRepositories ? ' — tous audités' : n.selectedRepositoryCount ? ' — ' + n.selectedRepositoryCount + ' sélectionné(s)' : '' }}
                </span>
              </div>
              <div class="row actions">
                <label class="inline">
                  <input type="checkbox" [checked]="n.selected" [disabled]="!isAdmin() || busy()"
                         (change)="select(n, $any($event.target).checked, n.includeAllRepositories)" />
                  Auditer cette organisation
                </label>
                @if (n.selected) {
                  <label class="inline">
                    <input type="checkbox" [checked]="n.includeAllRepositories" [disabled]="!isAdmin() || busy()"
                           (change)="select(n, true, $any($event.target).checked)" />
                    Tous les dépôts (y compris futurs)
                  </label>
                }
                <span class="spacer"></span>
                @if (isAdmin()) {
                  <button type="button" (click)="discoverRepositories(n)" [disabled]="busy()">Charger les dépôts</button>
                }
                <button type="button" (click)="toggleExpanded(n.id)" [attr.aria-expanded]="expanded().has(n.id)">
                  {{ expanded().has(n.id) ? 'Masquer' : 'Voir les dépôts' }}
                </button>
              </div>
              @if (n.repositoriesSyncedAt) {
                <p class="muted sync">Dépôts synchronisés le {{ n.repositoriesSyncedAt | date: 'short' }}
                  {{ n.repositoriesSyncStatus === 'OK' ? '' : '— ' + (n.repositoriesSyncMessage ?? n.repositoriesSyncStatus) }}</p>
              }
              @if (expanded().has(n.id)) {
                <acs-namespace-repositories [namespace]="n" [canEdit]="isAdmin()" (changed)="reloadNamespaces()" />
              }
            </li>
          }
        </ul>
      } @else if (connectionId() && !loading()) {
        <section class="card empty">
          <p>Aucune organisation connue pour cette connexion.</p>
          <p class="muted">{{ isAdmin() ? 'Cliquez sur « Découvrir les organisations », ou ajoutez-en une par son nom.' : 'Un administrateur doit lancer la découverte.' }}</p>
        </section>
      }
    }
  `,
  styles: `
    .page-header { margin-bottom: 16px; }
    h1 { margin: 0; font-size: 1.5rem; }
    .controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
    .controls label { display: flex; flex-direction: column; gap: 4px; font-size: .9rem; font-weight: 500; flex: 1; min-width: 200px; }
    select, input:not([type=checkbox]) { font: inherit; padding: .5rem .6rem; border-radius: 6px; border: 1px solid var(--acs-border);
                                         background: var(--acs-bg); color: var(--acs-text); }
    .add { display: flex; gap: 8px; margin: 12px 0; }
    .add input { flex: 1; min-width: 0; }
    .filter { width: 100%; margin: 4px 0 12px; }
    .tree { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
    .tree li.removed { opacity: .7; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; }
    .actions { margin-top: 8px; justify-content: flex-start; }
    .spacer { flex: 1; }
    .title { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; overflow-wrap: anywhere; }
    .badge { font-size: .72rem; padding: .1rem .5rem; border-radius: 999px; background: var(--acs-hover); }
    .badge.warn { color: var(--acs-medium); }
    .counts { font-size: .85rem; }
    .sync { font-size: .8rem; margin: 6px 0 0; }
    label.inline { display: flex; gap: 6px; align-items: center; font-size: .9rem; }
    .message { margin: 12px 0; }
    .error { color: var(--acs-critical); }
    button { font: inherit; font-size: .9rem; padding: .45rem .85rem; border-radius: 6px; border: 1px solid var(--acs-border);
             background: var(--acs-surface); color: var(--acs-text); cursor: pointer; }
    button.primary { background: var(--acs-accent); border-color: var(--acs-accent); color: #fff; }
    button:disabled { opacity: .6; }
    @media (max-width: 640px) { .tree li { margin-left: 0 !important; } }
  `,
})
export class RepositoriesPage implements OnInit {
  private readonly connectionsApi = inject(ConnectionsApi);
  private readonly api = inject(SourcesApi);
  private readonly auth = inject(AuthService);

  readonly connections = signal<GitConnection[]>([]);
  readonly connectionId = signal<string | null>(null);
  readonly namespaces = signal<Namespace[]>([]);
  readonly filter = signal('');
  readonly expanded = signal<Set<string>>(new Set());
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly message = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly isAdmin = computed(() => this.auth.hasRole('ADMIN'));
  readonly rows = computed(() => filterTree(orderTree(this.namespaces()), this.filter()));

  ngOnInit(): void {
    this.connectionsApi.list().subscribe({
      next: list => {
        this.connections.set(list);
        this.loading.set(false);
        if (list.length) {
          this.selectConnection(list[0].id);
        }
      },
      error: e => {
        this.loading.set(false);
        this.error.set(errorMessage(e));
      },
    });
  }

  kindLabel(n: Namespace): string {
    return KIND_LABELS[n.kind] ?? n.kind;
  }

  selectConnection(id: string): void {
    this.connectionId.set(id);
    this.message.set(null);
    this.expanded.set(new Set());
    this.reloadNamespaces();
  }

  reloadNamespaces(): void {
    const id = this.connectionId();
    if (!id) {
      return;
    }
    this.api.namespaces(id).subscribe({
      next: list => this.namespaces.set(list),
      error: e => this.error.set(errorMessage(e)),
    });
  }

  discover(): void {
    const id = this.connectionId();
    if (!id) {
      return;
    }
    this.run(this.api.discoverNamespaces(id), r => this.message.set(discoveryMessage(r)));
  }

  add(path: string): void {
    const id = this.connectionId();
    if (!id || !path.trim()) {
      return;
    }
    this.run(this.api.addNamespace(id, path.trim()), n => this.message.set(`« ${n.fullPath} » ajouté.`));
  }

  discoverRepositories(n: Namespace): void {
    this.run(this.api.discoverRepositories(n.id), r => {
      this.message.set(`${n.fullPath} — ${discoveryMessage(r)}`);
      this.expanded.update(s => new Set(s).add(n.id));
    });
  }

  select(n: Namespace, selected: boolean, includeAll: boolean): void {
    this.run(this.api.selectNamespace(n.id, selected, includeAll), () => undefined);
  }

  toggleExpanded(id: string): void {
    this.expanded.update(s => {
      const next = new Set(s);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  private run<T>(call: Observable<T>, onSuccess: (value: T) => void): void {
    this.busy.set(true);
    this.error.set(null);
    call.subscribe({
      next: value => {
        this.busy.set(false);
        onSuccess(value);
        this.reloadNamespaces();
      },
      error: e => {
        this.busy.set(false);
        this.error.set(errorMessage(e));
      },
    });
  }
}
