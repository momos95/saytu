import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';
import { errorMessage } from '../connections/connections.api';
import { PageView } from '../repositories/sources.model';
import { LanguageChips, ScoreBadges } from '../../shared/score-badges';
import { AuditsApi } from './audits.api';
import {
  RUN_STATUS_LABELS,
  SEVERITY_LABELS,
  SHORT_SCANNER_LABELS,
  describeExecution,
  elapsed,
  executionTone,
  formatBytes,
  formatDuration,
  isActive,
  location,
  progress,
  scopeLabel,
  shortSha,
} from './audits.logic';
import { FindingPage, ScanJob, ScanRun, ScanRunDetail } from './audits.model';

/** Page 6: launch audits, follow their progress per branch and scanner, look at the results. */
@Component({
  selector: 'saytu-audits-page',
  imports: [DatePipe, LanguageChips, ScoreBadges],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="page-header">
      <h1>Audits</h1>
      @if (canAudit()) {
        <button type="button" class="primary" (click)="launch()" [disabled]="busy()" data-testid="launch">
          Auditer tous les dépôts sélectionnés
        </button>
      }
    </header>
    <p class="muted intro">
      Chaque branche est clonée sans exécuter aucun script du dépôt, puis analysée par Opengrep, Trivy et Gitleaks.
      Un scanner en échec n’est jamais compté comme « aucune vulnérabilité ».
    </p>

    @if (error()) {
      <p class="error" role="alert">{{ error() }}</p>
    }

    @if (runs(); as p) {
      @if (p.items.length === 0) {
        <section class="card"><p class="muted">Aucun audit pour l’instant.</p></section>
      } @else {
        <ul class="runs">
          @for (r of p.items; track r.id) {
            <li class="card run" [class.selected]="selected()?.run?.id === r.id" data-testid="run">
              <button type="button" class="run-open" (click)="open(r.id)">
                <span class="status" [attr.data-status]="r.status">{{ statusLabel(r.status) }}</span>
                <span class="when">{{ r.createdAt | date: 'dd/MM/yyyy HH:mm' }}</span>
                <span class="muted">{{ scope(r.scope) }} · {{ r.requestedBy }}</span>
                <span class="progress">{{ progressOf(r) }}</span>
                @if (r.newFindings > 0) { <span class="badge">{{ r.newFindings }} nouveau(x)</span> }
                @if (r.problemJobs > 0) { <span class="badge warn">{{ r.problemJobs }} incomplet(s)</span> }
              </button>
            </li>
          }
        </ul>
        @if (p.totalPages > 1) {
          <nav class="pager">
            <button type="button" (click)="loadRuns(p.page - 1)" [disabled]="p.page === 0">Précédent</button>
            <span>Page {{ p.page + 1 }} / {{ p.totalPages }}</span>
            <button type="button" (click)="loadRuns(p.page + 1)" [disabled]="p.page + 1 >= p.totalPages">Suivant</button>
          </nav>
        }
      }
    }

    @if (selected(); as d) {
      <section class="card detail" data-testid="detail">
        <div class="row">
          <h2>Audit du {{ d.run.createdAt | date: 'dd/MM/yyyy HH:mm' }}</h2>
          <span class="status" [attr.data-status]="d.run.status">{{ statusLabel(d.run.status) }}</span>
        </div>
        <p class="muted">
          {{ scope(d.run.scope) }} · demandé par {{ d.run.requestedBy }} · {{ progressOf(d.run) }}
          @if (d.run.startedAt) { · durée {{ elapsedOf(d.run.startedAt, d.run.finishedAt) }} }
        </p>
        @if (d.run.errorMessage) { <p class="error">{{ d.run.errorMessage }}</p> }
        @if (canAudit() && active(d.run) && !d.run.cancelRequested) {
          <button type="button" (click)="cancel(d.run.id)" [disabled]="busy()">Annuler l’audit</button>
        }
        @if (d.run.cancelRequested && active(d.run)) { <p class="muted">Annulation demandée : les analyses en cours s’arrêtent avant leur prochain scanner.</p> }

        @if (d.planningNotes.length) {
          <details class="notes">
            <summary>{{ d.planningNotes.length }} dépôt(s) ou branche(s) non analysé(s)</summary>
            <ul>
              @for (n of d.planningNotes; track $index) { <li><strong>{{ n.repository }}</strong> — {{ n.note }}</li> }
            </ul>
          </details>
        }

        <ul class="jobs">
          @for (j of d.jobs; track j.id) {
            <li class="job" data-testid="job">
              <div class="row">
                <span class="name">{{ j.repositoryName }} <span class="branch">⎇ {{ j.branch }}</span></span>
                <span class="status" [attr.data-status]="j.status">{{ statusLabel(j.status) }}</span>
              </div>
              <p class="muted meta">
                @if (j.commitSha) { commit {{ sha(j.commitSha) }} · }
                @if (j.checkoutBytes) { {{ bytes(j.checkoutBytes) }} · }
                @if (j.startedAt) { {{ elapsedOf(j.startedAt, j.finishedAt) }} · }
                {{ j.findingsCount }} résultat(s), {{ j.newFindings }} nouveau(x), {{ j.resolvedFindings }} corrigé(s)
                @if (j.attempt > 1) { · tentative {{ j.attempt }} }
              </p>
              @if (j.languages.length || j.score) {
                <div class="row lang-score">
                  <saytu-language-chips [languages]="j.languages" />
                  @if (j.score) { <saytu-score-badges [score]="j.score" /> }
                </div>
              }
              @if (j.errorMessage) { <p class="error small">{{ j.errorMessage }}</p> }
              <ul class="executions">
                @for (e of j.scanners; track e.scanner) {
                  <li [attr.data-tone]="tone(e.status)" [title]="executionTitle(e.toolVersion, e.rulesetVersion, e.errorMessage)">
                    {{ describe(e) }}
                    @if (e.durationMs) { <span class="muted"> · {{ duration(e.durationMs) }}</span> }
                  </li>
                }
              </ul>
              @if (j.findingsCount > 0) {
                <button type="button" (click)="toggleFindings(j)">
                  {{ expanded() === j.id ? 'Masquer les résultats' : 'Voir les résultats' }}
                </button>
              }
              @if (expanded() === j.id) {
                @if (findings()[j.id]; as f) {
                  <p class="muted small">
                    {{ f.page.totalElements }} vulnérabilité(s) ouverte(s) sur cette branche :
                    @for (s of severities; track s) { {{ severityLabel(s) }} {{ f.bySeverity[s] }}@if (!$last) { · } }
                  </p>
                  <table class="findings">
                    <thead><tr><th>Sévérité</th><th>Problème</th><th>Emplacement</th><th>Scanner</th></tr></thead>
                    <tbody>
                      @for (x of f.page.items; track x.id) {
                        <tr>
                          <td><span class="sev" [attr.data-severity]="x.severity">{{ severityLabel(x.severity) }}</span></td>
                          <td>{{ x.title }}<br /><span class="muted small">{{ x.ruleId }}@if (x.cwes.length) { · {{ x.cwes.join(', ') }} }</span></td>
                          <td class="loc">{{ where(x) }}</td>
                          <td>{{ scannerNames(x.scanners) }}</td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  @if (f.page.totalElements > f.page.items.length) {
                    <p class="muted small">{{ f.page.items.length }} premiers résultats affichés (liste complète et filtres : page Vulnérabilités, phase 6).</p>
                  }
                } @else {
                  <p class="muted small">Chargement…</p>
                }
              }
            </li>
          }
        </ul>
      </section>
    }
  `,
  styles: `
    .page-header { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; margin-bottom: 8px; }
    h1 { margin: 0; font-size: 1.5rem; }
    h2 { margin: 0; font-size: 1.15rem; }
    .intro { margin: 0 0 16px; font-size: .9rem; }
    .runs, .jobs, .executions { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
    .run { padding: 0; }
    .run.selected { outline: 2px solid var(--saytu-accent); }
    .run-open { width: 100%; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; text-align: left;
                background: none; border: 0; padding: 12px 14px; color: var(--saytu-text); cursor: pointer; font: inherit; }
    .when { font-weight: 600; }
    .progress { margin-left: auto; font-size: .9rem; }
    .status { font-size: .75rem; font-weight: 600; padding: .15rem .55rem; border-radius: 999px; background: var(--saytu-hover); white-space: nowrap; }
    .status[data-status="SUCCEEDED"] { background: var(--saytu-accent-soft); color: var(--saytu-accent); }
    .status[data-status="PARTIAL"] { background: color-mix(in srgb, var(--saytu-medium) 18%, transparent); color: var(--saytu-medium); }
    .status[data-status="FAILED"] { background: color-mix(in srgb, var(--saytu-critical) 15%, transparent); color: var(--saytu-critical); }
    .status[data-status="RUNNING"], .status[data-status="QUEUED"] { background: color-mix(in srgb, var(--saytu-info) 15%, transparent); color: var(--saytu-info); }
    .badge { font-size: .72rem; padding: .1rem .5rem; border-radius: 999px; background: var(--saytu-hover); }
    .badge.warn { color: var(--saytu-medium); }
    .detail { margin-top: 18px; display: flex; flex-direction: column; gap: 10px; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; }
    .job { border-top: 1px solid var(--saytu-border); padding-top: 10px; display: flex; flex-direction: column; gap: 6px; }
    .name { font-weight: 600; overflow-wrap: anywhere; }
    .branch { font-weight: 400; color: var(--saytu-muted); margin-left: 6px; }
    .meta { margin: 0; font-size: .85rem; }
    .executions { flex-direction: row; flex-wrap: wrap; gap: 6px; }
    .lang-score { gap: 10px; flex-wrap: wrap; justify-content: flex-start; margin: 4px 0 8px; }
    .executions li { font-size: .8rem; padding: .2rem .55rem; border-radius: 6px; border: 1px solid var(--saytu-border); }
    .executions li[data-tone="ok"] { border-color: var(--saytu-accent); }
    .executions li[data-tone="warn"] { border-color: var(--saytu-medium); color: var(--saytu-medium); }
    .executions li[data-tone="muted"] { color: var(--saytu-muted); }
    .notes summary { cursor: pointer; }
    .findings { width: 100%; border-collapse: collapse; font-size: .85rem; display: block; overflow-x: auto; }
    .findings th, .findings td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--saytu-border); vertical-align: top; }
    .loc { overflow-wrap: anywhere; font-family: ui-monospace, monospace; font-size: .8rem; }
    .sev { font-weight: 600; font-size: .78rem; }
    .sev[data-severity="CRITICAL"] { color: var(--saytu-critical); }
    .sev[data-severity="HIGH"] { color: var(--saytu-high); }
    .sev[data-severity="MEDIUM"] { color: var(--saytu-medium); }
    .sev[data-severity="LOW"] { color: var(--saytu-low); }
    .sev[data-severity="INFO"] { color: var(--saytu-info); }
    .small { font-size: .8rem; margin: 0; }
    .pager { display: flex; gap: 8px; justify-content: center; align-items: center; margin-top: 10px; }
    .error { color: var(--saytu-critical); }
    button { font: inherit; font-size: .9rem; padding: .4rem .8rem; border-radius: 6px; border: 1px solid var(--saytu-border);
             background: var(--saytu-surface); color: var(--saytu-text); cursor: pointer; align-self: flex-start; }
    button.primary { background: var(--saytu-accent); border-color: var(--saytu-accent); color: #fff; }
    button:disabled { opacity: .6; }
  `,
})
export class AuditsPage implements OnInit {
  private readonly api = inject(AuditsApi);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);

  readonly runs = signal<PageView<ScanRun> | null>(null);
  readonly selected = signal<ScanRunDetail | null>(null);
  readonly findings = signal<Record<string, FindingPage>>({});
  readonly expanded = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly canAudit = computed(() => this.auth.hasRole('AUDITOR') || this.auth.hasRole('ADMIN'));
  readonly severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

  ngOnInit(): void {
    this.loadRuns(0);
    const timer = setInterval(() => this.refreshIfActive(), 5000);
    this.destroyRef.onDestroy(() => clearInterval(timer));
  }

  loadRuns(page: number): void {
    this.api.runs(Math.max(0, page), 20).subscribe({
      next: p => this.runs.set(p),
      error: e => this.error.set(errorMessage(e)),
    });
  }

  open(id: string): void {
    this.expanded.set(null);
    this.api.run(id).subscribe({
      next: d => this.selected.set(d),
      error: e => this.error.set(errorMessage(e)),
    });
  }

  launch(): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.request({ allTargets: true }).subscribe({
      next: created => {
        this.busy.set(false);
        this.loadRuns(0);
        this.open(created.id);
      },
      error: e => {
        this.busy.set(false);
        this.error.set(errorMessage(e));
      },
    });
  }

  cancel(id: string): void {
    this.busy.set(true);
    this.api.cancel(id).subscribe({
      next: d => {
        this.busy.set(false);
        this.selected.set(d);
        this.loadRuns(this.runs()?.page ?? 0);
      },
      error: e => {
        this.busy.set(false);
        this.error.set(errorMessage(e));
      },
    });
  }

  toggleFindings(job: ScanJob): void {
    if (this.expanded() === job.id) {
      this.expanded.set(null);
      return;
    }
    this.expanded.set(job.id);
    this.api.findings({ repositoryId: job.repositoryId, branch: job.branch, status: ['OPEN'] }, 0, 50).subscribe({
      next: f => this.findings.update(all => ({ ...all, [job.id]: f })),
      error: e => this.error.set(errorMessage(e)),
    });
  }

  private refreshIfActive(): void {
    const list = this.runs();
    if (list && list.items.some(isActive)) {
      this.loadRuns(list.page);
    }
    const d = this.selected();
    if (d && isActive(d.run)) {
      this.api.run(d.run.id).subscribe({ next: next => this.selected.set(next) });
    }
  }

  // template helpers
  statusLabel(s: ScanRun['status']): string {
    return RUN_STATUS_LABELS[s];
  }

  severityLabel(s: string): string {
    return SEVERITY_LABELS[s] ?? s;
  }

  scope(s: string | null): string {
    return scopeLabel(s);
  }

  progressOf(r: ScanRun): string {
    return progress(r);
  }

  active(r: ScanRun): boolean {
    return isActive(r);
  }

  elapsedOf(from: string | null, to: string | null): string {
    return elapsed(from, to);
  }

  readonly describe = describeExecution;
  readonly tone = executionTone;
  readonly duration = formatDuration;
  readonly bytes = formatBytes;
  readonly where = location;
  readonly sha = shortSha;

  executionTitle(tool: string | null, ruleset: string | null, error: string | null): string {
    return [tool ? `version ${tool}` : '', ruleset ? `règles / base : ${ruleset}` : '', error ?? ''].filter(Boolean).join('\n');
  }

  scannerNames(ids: string[]): string {
    return ids.map(i => SHORT_SCANNER_LABELS[i] ?? i).join(', ');
  }
}
