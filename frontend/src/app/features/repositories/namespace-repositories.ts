import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { errorMessage } from '../connections/connections.api';
import { SourcesApi } from './sources.api';
import { Namespace, PageView, Repository } from './sources.model';

/** Paginated, searchable repositories of one namespace, with selection checkboxes (ADMIN). */
@Component({
  selector: 'acs-namespace-repositories',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="toolbar">
      <input type="search" placeholder="Filtrer les dépôts…" [value]="query()" (input)="onSearch($event)"
             aria-label="Filtrer les dépôts" />
      @if (canEdit() && !namespace().includeAllRepositories) {
        <button type="button" (click)="selectPage(true)" [disabled]="busy() || !page()?.items?.length">Tout cocher (page)</button>
        <button type="button" (click)="selectPage(false)" [disabled]="busy() || !page()?.items?.length">Tout décocher (page)</button>
      }
    </div>
    @if (namespace().includeAllRepositories) {
      <p class="muted note">Tous les dépôts de « {{ namespace().fullPath }} » sont audités, y compris les futurs.</p>
    }
    @if (error()) {
      <p class="error" role="alert">{{ error() }}</p>
    }
    @if (page(); as p) {
      @if (p.items.length === 0) {
        <p class="muted">{{ query() ? 'Aucun dépôt ne correspond.' : 'Aucun dépôt chargé : cliquez sur « Charger les dépôts ».' }}</p>
      } @else {
        <ul class="repos">
          @for (r of p.items; track r.id) {
            <li data-testid="repository">
              <label>
                <input type="checkbox" [checked]="r.selected || namespace().includeAllRepositories"
                       [disabled]="!canEdit() || namespace().includeAllRepositories || busy()"
                       (change)="toggle(r, $any($event.target).checked)" />
                <span class="name">{{ r.fullName }}</span>
              </label>
              <span class="tags">
                @if (r.defaultBranch) { <span class="tag">{{ r.defaultBranch }}</span> }
                @if (r.visibility === 'PUBLIC') { <span class="tag">public</span> }
                @if (r.archived) { <span class="tag warn">archivé (ignoré)</span> }
                @if (r.scanTarget) { <span class="tag ok">audité</span> }
              </span>
            </li>
          }
        </ul>
        @if (p.totalPages > 1) {
          <nav class="pager" aria-label="Pages de dépôts">
            <button type="button" (click)="load(p.page - 1)" [disabled]="p.page === 0">Précédent</button>
            <span>Page {{ p.page + 1 }} / {{ p.totalPages }} — {{ p.totalElements }} dépôts</span>
            <button type="button" (click)="load(p.page + 1)" [disabled]="p.page + 1 >= p.totalPages">Suivant</button>
          </nav>
        }
      }
    }
  `,
  styles: `
    :host { display: block; margin-top: 10px; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
    input[type=search] { flex: 1; min-width: 180px; font: inherit; padding: .4rem .6rem; border-radius: 6px;
                         border: 1px solid var(--acs-border); background: var(--acs-bg); color: var(--acs-text); }
    .repos { list-style: none; margin: 0; padding: 0; }
    .repos li { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 6px; padding: 6px 0;
                border-top: 1px solid var(--acs-border); }
    label { display: flex; gap: 8px; align-items: center; min-width: 0; }
    .name { overflow-wrap: anywhere; }
    .tags { display: flex; gap: 4px; flex-wrap: wrap; }
    .tag { font-size: .72rem; padding: .05rem .45rem; border-radius: 999px; background: var(--acs-hover); }
    .tag.ok { background: var(--acs-accent-soft); color: var(--acs-accent); }
    .tag.warn { color: var(--acs-medium); }
    .pager { display: flex; gap: 8px; align-items: center; justify-content: center; margin-top: 8px; font-size: .85rem; }
    .note { font-size: .85rem; margin: 0 0 6px; }
    .error { color: var(--acs-critical); }
    button { font: inherit; font-size: .85rem; padding: .35rem .7rem; border-radius: 6px; border: 1px solid var(--acs-border);
             background: var(--acs-surface); color: var(--acs-text); cursor: pointer; }
    button:disabled { opacity: .6; }
  `,
})
export class NamespaceRepositories {
  private readonly api = inject(SourcesApi);

  readonly namespace = input.required<Namespace>();
  readonly canEdit = input(false);
  /** Emitted after a selection change, so that the parent refreshes its counters. */
  readonly changed = output<void>();

  readonly page = signal<PageView<Repository> | null>(null);
  readonly query = signal('');
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly pageSize = 50;
  private searchTimer: ReturnType<typeof setTimeout> | undefined;
  readonly currentPage = computed(() => this.page()?.page ?? 0);

  constructor() {
    // Reload when the namespace is re-synchronised or its selection mode changes.
    effect(() => {
      const n = this.namespace();
      void n.repositoriesSyncedAt;
      void n.includeAllRepositories;
      untracked(() => this.load(this.currentPage()));
    });
  }

  load(pageIndex: number): void {
    this.api.repositories(this.namespace().id, this.query(), Math.max(0, pageIndex), this.pageSize).subscribe({
      next: p => this.page.set(p),
      error: e => this.error.set(errorMessage(e)),
    });
  }

  onSearch(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.load(0), 300);
  }

  toggle(r: Repository, selected: boolean): void {
    this.update([r.id], selected);
  }

  selectPage(selected: boolean): void {
    const ids = (this.page()?.items ?? []).filter(r => !r.archived && r.selected !== selected).map(r => r.id);
    if (ids.length) {
      this.update(ids, selected);
    }
  }

  private update(ids: string[], selected: boolean): void {
    this.busy.set(true);
    this.api.selectRepositories(ids, selected).subscribe({
      next: () => {
        this.busy.set(false);
        this.load(this.currentPage());
        this.changed.emit();
      },
      error: e => {
        this.busy.set(false);
        this.error.set(errorMessage(e));
      },
    });
  }
}
