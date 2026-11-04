import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';
import { errorMessage } from '../connections/connections.api';
import { SourcesApi } from '../repositories/sources.api';
import {
  BRANCH_MODE_LABELS,
  BranchMode,
  PageView,
  Repository,
  SCANNER_LABELS,
  ScanTargetSummary,
  Scanner,
} from '../repositories/sources.model';
import { BranchPicker } from './branch-picker';

/** Page 5: which scanners run, with which limits, and which branches of the selected repositories. */
@Component({
  selector: 'acs-scan-settings-page',
  imports: [BranchPicker],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="page-header"><h1>Scanners et branches</h1></header>

    @if (error()) {
      <p class="error" role="alert">{{ error() }}</p>
    }

    @if (summary(); as s) {
      <section class="card summary" data-testid="summary">
        <div><strong>{{ s.repositories }}</strong><span class="muted">dépôts audités</span></div>
        <div><strong>{{ s.selectedNamespaces }}</strong><span class="muted">organisations</span></div>
        <div><strong>{{ s.defaultBranchMode }}</strong><span class="muted">branche par défaut</span></div>
        <div><strong>{{ s.presetBranchMode }}</strong><span class="muted">main/master/develop</span></div>
        <div><strong>{{ s.customBranchMode }}</strong><span class="muted">liste personnalisée</span></div>
      </section>
    }

    <h2>Scanners</h2>
    <p class="muted intro">Un scanner désactivé n’est jamais considéré comme « aucune vulnérabilité » : il réduit la couverture affichée avec les scores.</p>
    <ul class="scanners">
      @for (s of scanners(); track s.id) {
        <li class="card" data-testid="scanner">
          <div class="row">
            <label class="inline">
              <input type="checkbox" [checked]="s.enabled" [disabled]="!isAdmin()" (change)="edit(s, { enabled: $any($event.target).checked })" />
              <strong>{{ label(s.id) }}</strong>
            </label>
            @if (s.optional) { <span class="badge">optionnel</span> }
          </div>
          <div class="limits">
            <label>Délai max (s)
              <input type="number" min="30" max="21600" [value]="s.timeoutSeconds" [disabled]="!isAdmin()"
                     (change)="edit(s, { timeoutSeconds: +$any($event.target).value })" /></label>
            <label>Temps CPU max (s)
              <input type="number" min="1" max="86400" [value]="s.cpuSeconds" [disabled]="!isAdmin()"
                     (change)="edit(s, { cpuSeconds: +$any($event.target).value })" /></label>
            <label>Mémoire max (Mo)
              <input type="number" min="64" max="65536" [value]="s.memoryMb" [disabled]="!isAdmin()"
                     (change)="edit(s, { memoryMb: +$any($event.target).value })" /></label>
          </div>
          <p class="muted note">Intégré à la phase {{ s.id === 'pmd' || s.id === 'checkstyle' || s.id === 'dependency-check' ? 5 : 4 }}.</p>
        </li>
      }
    </ul>

    <h2>Branches à auditer</h2>
    <div class="toolbar">
      <input type="search" placeholder="Filtrer les dépôts…" (input)="onSearch($any($event.target).value)" aria-label="Filtrer les dépôts" />
      @if (isAdmin()) {
        <select #bulk aria-label="Mode de branches à appliquer">
          @for (m of modes; track m) { <option [value]="m">{{ modeLabel(m) }}</option> }
        </select>
        <button type="button" (click)="applyBulk($any(bulk.value))" [disabled]="busy() || checked().size === 0">
          Appliquer aux {{ checked().size }} dépôt(s) cochés
        </button>
      }
    </div>

    @if (targets(); as p) {
      @if (p.items.length === 0) {
        <section class="card"><p class="muted">Aucun dépôt dans le périmètre d’audit. Sélectionnez des organisations ou des dépôts dans « Organisations & dépôts ».</p></section>
      } @else {
        <ul class="targets">
          @for (r of p.items; track r.id) {
            <li class="card" data-testid="target">
              <div class="row">
                <label class="inline">
                  @if (isAdmin()) {
                    <input type="checkbox" [checked]="checked().has(r.id)" (change)="check(r.id, $any($event.target).checked)" />
                  }
                  <span class="name">{{ r.fullName }}</span>
                </label>
                <span class="muted conn">{{ r.connectionName }}</span>
              </div>
              <div class="row">
                <select [value]="r.branchMode" [disabled]="!isAdmin() || busy()" (change)="setMode([r.id], $any($event.target).value)"
                        aria-label="Branches à auditer">
                  @for (m of modes; track m) { <option [value]="m">{{ modeLabel(m) }}</option> }
                </select>
                <span class="muted branches">{{ describe(r) }}</span>
                @if (isAdmin() && r.branchMode === 'CUSTOM') {
                  <button type="button" (click)="editing.set(editing() === r.id ? null : r.id)">Choisir les branches</button>
                }
              </div>
              @if (editing() === r.id) {
                <acs-branch-picker [repository]="r" (saved)="onBranchesSaved()" (cancelled)="editing.set(null)" />
              }
            </li>
          }
        </ul>
        @if (p.totalPages > 1) {
          <nav class="pager">
            <button type="button" (click)="loadTargets(p.page - 1)" [disabled]="p.page === 0">Précédent</button>
            <span>Page {{ p.page + 1 }} / {{ p.totalPages }}</span>
            <button type="button" (click)="loadTargets(p.page + 1)" [disabled]="p.page + 1 >= p.totalPages">Suivant</button>
          </nav>
        }
      }
    }
  `,
  styles: `
    h1 { margin: 0 0 16px; font-size: 1.5rem; }
    h2 { font-size: 1.15rem; margin: 24px 0 6px; }
    .intro { margin: 0 0 10px; font-size: .9rem; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
    .summary div { display: flex; flex-direction: column; }
    .summary strong { font-size: 1.4rem; }
    .scanners, .targets { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; }
    .targets .row + .row { justify-content: flex-start; margin-top: 8px; }
    .limits { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 10px; }
    .limits label { display: flex; flex-direction: column; font-size: .8rem; gap: 2px; }
    .limits input { width: 110px; }
    input:not([type=checkbox]), select { font: inherit; padding: .4rem .55rem; border-radius: 6px; border: 1px solid var(--acs-border);
                                         background: var(--acs-bg); color: var(--acs-text); }
    label.inline { display: flex; gap: 8px; align-items: center; min-width: 0; }
    .name { overflow-wrap: anywhere; }
    .badge { font-size: .72rem; padding: .1rem .5rem; border-radius: 999px; background: var(--acs-hover); }
    .note { font-size: .78rem; margin: 6px 0 0; }
    .conn, .branches { font-size: .85rem; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
    .toolbar input { flex: 1; min-width: 180px; }
    .pager { display: flex; gap: 8px; justify-content: center; align-items: center; margin-top: 10px; }
    .error { color: var(--acs-critical); }
    button { font: inherit; font-size: .9rem; padding: .4rem .8rem; border-radius: 6px; border: 1px solid var(--acs-border);
             background: var(--acs-surface); color: var(--acs-text); cursor: pointer; }
    button:disabled { opacity: .6; }
  `,
})
export class ScanSettingsPage implements OnInit {
  private readonly api = inject(SourcesApi);
  private readonly auth = inject(AuthService);

  readonly modes: BranchMode[] = ['DEFAULT', 'PRESET', 'CUSTOM'];
  readonly scanners = signal<Scanner[]>([]);
  readonly summary = signal<ScanTargetSummary | null>(null);
  readonly targets = signal<PageView<Repository> | null>(null);
  readonly checked = signal<Set<string>>(new Set());
  readonly editing = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly isAdmin = computed(() => this.auth.hasRole('ADMIN'));
  private query = '';
  private searchTimer: ReturnType<typeof setTimeout> | undefined;

  ngOnInit(): void {
    this.api.scanners().subscribe({ next: s => this.scanners.set(s), error: e => this.error.set(errorMessage(e)) });
    this.loadSummary();
    this.loadTargets(0);
  }

  label(id: string): string {
    return SCANNER_LABELS[id] ?? id;
  }

  modeLabel(m: BranchMode): string {
    return BRANCH_MODE_LABELS[m];
  }

  describe(r: Repository): string {
    switch (r.branchMode) {
      case 'DEFAULT':
        return r.defaultBranch ? `→ ${r.defaultBranch}` : '→ branche par défaut (inconnue pour l’instant)';
      case 'PRESET':
        return '→ main, master, develop selon leur présence au moment du scan';
      case 'CUSTOM':
        return r.branches.length ? `→ ${r.branches.join(', ')}` : '→ aucune branche choisie';
    }
  }

  edit(s: Scanner, change: Partial<Scanner>): void {
    const next = { ...s, ...change };
    this.api.updateScanner(next).subscribe({
      next: updated => this.scanners.update(list => list.map(x => (x.id === updated.id ? updated : x))),
      error: e => {
        this.error.set(errorMessage(e));
        this.scanners.update(list => [...list]); // re-render original values
      },
    });
  }

  onSearch(value: string): void {
    this.query = value;
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.loadTargets(0), 300);
  }

  loadTargets(page: number): void {
    this.api.scanTargets(this.query, Math.max(0, page), 50).subscribe({
      next: p => this.targets.set(p),
      error: e => this.error.set(errorMessage(e)),
    });
  }

  check(id: string, value: boolean): void {
    this.checked.update(s => {
      const next = new Set(s);
      if (value) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  }

  applyBulk(mode: BranchMode): void {
    this.setMode([...this.checked()], mode);
    this.checked.set(new Set());
  }

  setMode(ids: string[], mode: BranchMode): void {
    if (!ids.length) {
      return;
    }
    this.busy.set(true);
    this.api.setBranchMode(ids, mode).subscribe({
      next: () => {
        this.busy.set(false);
        this.refresh();
        if (mode === 'CUSTOM' && ids.length === 1) {
          this.editing.set(ids[0]);
        }
      },
      error: e => {
        this.busy.set(false);
        this.error.set(errorMessage(e));
      },
    });
  }

  onBranchesSaved(): void {
    this.editing.set(null);
    this.refresh();
  }

  private refresh(): void {
    this.loadSummary();
    this.loadTargets(this.targets()?.page ?? 0);
  }

  private loadSummary(): void {
    this.api.summary().subscribe({ next: s => this.summary.set(s), error: e => this.error.set(errorMessage(e)) });
  }
}
