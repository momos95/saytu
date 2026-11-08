import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ReportDownload } from '../../shared/report-download';
import { SEVERITY_LABELS, SHORT_SCANNER_LABELS, location } from '../audits/audits.logic';
import { Finding, FindingPage } from '../audits/audits.model';
import { InsightsApi } from './insights.api';
import { SEVERITIES, STATUSES, STATUS_LABELS, TYPES, TYPE_LABELS, filtersFromParams, filtersToParams, toggle } from './insights.logic';
import { FindingFilters } from './insights.model';

/** Findings of every audited repository, filterable; the filters live in the URL (shareable, back button). */
@Component({
  selector: 'saytu-findings-page',
  imports: [DatePipe, RouterLink, ReportDownload],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="page-header">
      <h1>Vulnérabilités</h1>
      <saytu-report-download [filters]="filters()" />
    </header>

    <section class="card filters" aria-label="Filtres">
      <div class="filter-row">
        <span class="muted small">Criticité</span>
        <div class="chips">
          @for (s of severities; track s) {
            <button type="button" class="chip" [attr.aria-pressed]="has('severity', s)" (click)="flip('severity', s)">
              <span class="sev" [attr.data-severity]="s">{{ severityLabel(s) }}</span>
            </button>
          }
        </div>
      </div>
      <div class="filter-row">
        <span class="muted small">Type</span>
        <div class="chips">
          @for (t of types; track t) {
            <button type="button" class="chip" [attr.aria-pressed]="has('type', t)" (click)="flip('type', t)">{{ typeLabel(t) }}</button>
          }
        </div>
      </div>
      <div class="filter-row">
        <span class="muted small">Statut</span>
        <div class="chips">
          @for (s of statuses; track s) {
            <button type="button" class="chip" [attr.aria-pressed]="has('status', s)" (click)="flip('status', s)">{{ statusLabel(s) }}</button>
          }
        </div>
      </div>
      <form class="filter-row" (submit)="$event.preventDefault(); applyText(scanner.value, branch.value, q.value)">
        <label class="small">Scanner
          <select #scanner [value]="filters().scanner ?? ''">
            <option value="">tous</option>
            @for (s of scanners; track s) { <option [value]="s">{{ scannerLabel(s) }}</option> }
          </select>
        </label>
        <label class="small">Branche <input #branch type="text" [value]="filters().branch ?? ''" placeholder="ex. main" /></label>
        <label class="small grow">Recherche <input #q type="search" [value]="filters().q ?? ''" placeholder="titre, règle, fichier, CVE, paquet" /></label>
        <button type="submit" class="primary">Filtrer</button>
        @if (hasFilters()) { <button type="button" (click)="reset()">Réinitialiser</button> }
      </form>
      @if (filters().repositoryId) {
        <p class="small">Dépôt : <strong>{{ repositoryName() ?? filters().repositoryId }}</strong>
          <button type="button" class="link" (click)="clear('repositoryId')">retirer</button></p>
      }
    </section>

    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }

    @if (page(); as p) {
      <p class="summary small" data-testid="summary">
        {{ p.page.totalElements }} résultat(s) :
        @for (s of severities; track s) {
          <span class="sev" [attr.data-severity]="s">{{ severityLabel(s) }} {{ p.bySeverity[s] }}</span>@if (!$last) { · }
        }
      </p>
      @if (p.page.items.length === 0) {
        <section class="card"><p class="empty">Aucune vulnérabilité ne correspond à ces filtres.</p></section>
      } @else {
        <section class="card list">
          <div class="table-wrap">
            <table class="data">
              <thead><tr><th>Criticité</th><th>Problème</th><th>Dépôt · branche</th><th>Emplacement</th><th>Scanner</th><th>Statut</th><th>Vue depuis</th></tr></thead>
              <tbody>
                @for (f of p.page.items; track f.id) {
                  <tr data-testid="finding">
                    <td><span class="sev" [attr.data-severity]="f.severity">{{ severityLabel(f.severity) }}</span></td>
                    <td class="problem">
                      <a [routerLink]="['/findings', f.id]">{{ f.title }}</a>
                      <div class="muted small">{{ typeLabel(f.type) }} · {{ f.ruleId }}@for (c of f.cwes; track c) { · {{ c }} }@if (f.cve) { · {{ f.cve }} }</div>
                    </td>
                    <td class="repo"><a [routerLink]="['/repositories', f.repositoryId]">{{ f.repositoryName }}</a>
                      <div class="muted small">⎇ {{ f.branch }}</div></td>
                    <td class="mono">{{ where(f) }}</td>
                    <td>{{ scannersOf(f) }}</td>
                    <td><span class="pill" [attr.data-status]="f.status">{{ statusLabel(f.status) }}</span></td>
                    <td class="small">{{ f.firstSeenAt | date: 'dd/MM/yyyy' }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
          @if (p.page.totalPages > 1) {
            <nav class="pager" aria-label="Pages">
              <button type="button" (click)="go(p.page.page - 1)" [disabled]="p.page.page === 0">Précédent</button>
              <span class="small">page {{ p.page.page + 1 }} / {{ p.page.totalPages }}</span>
              <button type="button" (click)="go(p.page.page + 1)" [disabled]="p.page.page + 1 >= p.page.totalPages">Suivant</button>
            </nav>
          }
        </section>
      }
    } @else if (!error()) {
      <p class="muted">Chargement…</p>
    }
  `,
  styleUrl: '../../shared/page.css',
  styles: `
    .filters { display: flex; flex-direction: column; gap: 10px; margin-bottom: 12px; }
    .filter-row { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; }
    .filter-row > .muted { width: 70px; }
    label { display: flex; flex-direction: column; gap: 3px; }
    label.grow { flex: 1 1 220px; }
    input, select { font: inherit; font-size: .88rem; padding: .35rem .5rem; border-radius: 6px; border: 1px solid var(--saytu-border);
                    background: var(--saytu-surface); color: var(--saytu-text); min-width: 0; }
    form button { align-self: flex-end; }
    button.link { border: 0; background: none; color: var(--saytu-accent); padding: 0 4px; font-size: .82rem; }
    .summary { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 8px; }
    .problem a { font-weight: 600; }
    .problem { min-width: 220px; }
    .repo { overflow-wrap: anywhere; min-width: 120px; }
    .pager { display: flex; gap: 8px; justify-content: center; align-items: center; margin-top: 12px; }
  `,
})
export class FindingsPage implements OnInit {
  private readonly api = inject(InsightsApi);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  readonly severities = SEVERITIES;
  readonly types = TYPES;
  readonly statuses = STATUSES;
  readonly scanners = Object.keys(SHORT_SCANNER_LABELS);
  readonly filters = signal<FindingFilters>({});
  readonly page = signal<FindingPage | null>(null);
  readonly error = signal<string | null>(null);
  readonly repositoryName = signal<string | null>(null);
  private pageIndex = 0;

  ngOnInit(): void {
    const sub = this.route.queryParams.subscribe(params => {
      if (Object.keys(params).length === 0) {
        // default view: what still needs work
        this.navigate({ status: ['OPEN'] }, true);
        return;
      }
      this.filters.set(filtersFromParams(params));
      this.pageIndex = Math.max(0, Number(params['page'] ?? 0) || 0);
      this.load();
    });
    this.destroyRef.onDestroy(() => sub.unsubscribe());
  }

  load(): void {
    this.error.set(null);
    this.api.findings(this.filters(), this.pageIndex).subscribe({
      next: p => {
        this.page.set(p);
        const repo = this.filters().repositoryId;
        this.repositoryName.set(repo ? (p.page.items.find(f => f.repositoryId === repo)?.repositoryName ?? null) : null);
      },
      error: () => this.error.set('La liste n’a pas pu être chargée (filtre invalide ?).'),
    });
  }

  has(key: 'severity' | 'type' | 'status', value: string): boolean {
    return this.filters()[key]?.includes(value) ?? false;
  }

  flip(key: 'severity' | 'type' | 'status', value: string): void {
    this.navigate({ ...this.filters(), [key]: toggle(this.filters()[key], value) });
  }

  applyText(scanner: string, branch: string, q: string): void {
    this.navigate({ ...this.filters(), scanner: scanner || undefined, branch: branch.trim() || undefined, q: q.trim() || undefined });
  }

  clear(key: keyof FindingFilters): void {
    this.navigate({ ...this.filters(), [key]: undefined });
  }

  reset(): void {
    this.navigate({ status: ['OPEN'] });
  }

  hasFilters(): boolean {
    return Object.keys(filtersToParams(this.filters())).length > 0;
  }

  go(page: number): void {
    this.router.navigate([], { relativeTo: this.route, queryParams: { ...filtersToParams(this.filters()), page } });
  }

  private navigate(filters: FindingFilters, replace = false): void {
    const params = filtersToParams(filters);
    // an empty filter set is shown as "status: all" rather than falling back to the default
    this.router.navigate([], { relativeTo: this.route, queryParams: Object.keys(params).length ? params : { all: '1' },
      replaceUrl: replace });
  }

  severityLabel(s: string): string {
    return SEVERITY_LABELS[s] ?? s;
  }

  typeLabel(t: string): string {
    return TYPE_LABELS[t] ?? t;
  }

  statusLabel(s: string): string {
    return STATUS_LABELS[s] ?? s;
  }

  scannerLabel(s: string): string {
    return SHORT_SCANNER_LABELS[s] ?? s;
  }

  scannersOf(f: Finding): string {
    const list = f.scanners.length ? f.scanners : [f.scanner];
    return list.map(s => SHORT_SCANNER_LABELS[s] ?? s).join(', ');
  }

  where(f: Finding): string {
    return location(f);
  }
}
