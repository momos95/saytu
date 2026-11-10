import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FlowChart, SeverityBreakdown, TrendChart } from '../../shared/charts';
import { ReportDownload } from '../../shared/report-download';
import { LanguageChips, ScoreBadges } from '../../shared/score-badges';
import { WorkflowBadge } from '../../shared/workflow-badge';
import { RELIABILITY_LABELS, RUN_STATUS_LABELS, formatScore, progress, scoreTone, scopeLabel } from '../audits/audits.logic';
import { ScanRun } from '../audits/audits.model';
import { InsightsApi } from '../findings/insights.api';
import { Dashboard } from '../findings/insights.model';

@Component({
  selector: 'saytu-dashboard-page',
  imports: [DatePipe, RouterLink, ScoreBadges, LanguageChips, WorkflowBadge, TrendChart, FlowChart, SeverityBreakdown, ReportDownload],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="page-header">
      <h1>Tableau de bord</h1>
      <saytu-report-download [filters]="{}" />
    </header>

    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }

    @if (data(); as d) {
      @if (d.counters.auditedRepositories === 0) {
        <section class="card">
          <p class="empty">Aucun dépôt audité pour l’instant. Sélectionnez des dépôts dans
            <a routerLink="/repositories">Organisations &amp; dépôts</a>, puis lancez un audit depuis la page
            <a routerLink="/audits">Audits</a>. Rien n’est affiché tant qu’aucune analyse réelle n’a abouti.</p>
        </section>
      } @else {
        <section class="grid scores">
          @for (s of scoreCards(d); track s.label) {
            <div class="card score-card" [attr.data-tone]="tone(s.value)" data-testid="score-card">
              <span class="muted">{{ s.label }}</span>
              <strong>{{ fmt(s.value) }}</strong>
              <span class="small muted">{{ s.note }}</span>
            </div>
          }
        </section>

        <section class="card kpis-card">
          <div class="kpis">
            <a class="kpi" routerLink="/findings" [queryParams]="{ status: 'OPEN' }"><strong>{{ d.counters.openFindings }}</strong><span>vulnérabilités ouvertes</span></a>
            <div class="kpi"><strong>{{ d.counters.newLast7Days }}</strong><span>nouvelles (7 jours)</span></div>
            <div class="kpi"><strong>{{ d.counters.resolvedLast7Days }}</strong><span>corrigées (7 jours)</span></div>
            <a class="kpi" routerLink="/findings" [queryParams]="{ status: 'ACCEPTED_RISK,FALSE_POSITIVE' }"><strong>{{ d.counters.triaged }}</strong><span>risques acceptés / faux positifs</span></a>
            <div class="kpi"><strong>{{ d.counters.auditedRepositories }}</strong><span>dépôts audités</span></div>
            <div class="kpi" data-testid="workflow-kpi" title="main ou master sur le dernier tag de version, branche develop présente">
              <strong>{{ d.counters.workflowChecked ? d.counters.workflowPass + ' / ' + d.counters.workflowChecked : '—' }}</strong>
              <span>branches bien organisées@if (d.counters.workflowFail) { · {{ d.counters.workflowFail }} non conforme(s) }</span></div>
            <div class="kpi"><strong class="date">{{ d.counters.lastAuditAt ? (d.counters.lastAuditAt | date: 'dd/MM HH:mm') : '—' }}</strong><span>dernier audit terminé</span></div>
          </div>
        </section>

        <div class="grid">
          <section class="card">
            <h2>Vulnérabilités ouvertes par criticité</h2>
            <saytu-severity-breakdown [counts]="d.openBySeverity" />
          </section>
          <section class="card">
            <h2>Dépôts prioritaires</h2>
            @if (d.priorities.length === 0) {
              <p class="empty">Aucun dépôt avec un score ou une vulnérabilité ouverte.</p>
            } @else {
              <ol class="priorities">
                @for (p of d.priorities; track p.repositoryId) {
                  <li data-testid="priority">
                    <div class="row">
                      <a [routerLink]="['/repositories', p.repositoryId]" class="name">{{ p.repository }}</a>
                      <saytu-language-chips [languages]="p.languages" />
                      <saytu-workflow-badge [status]="p.workflowStatus" />
                    </div>
                    <div class="row small">
                      @if (p.critical > 0) { <span class="sev" data-severity="CRITICAL">{{ p.critical }} critique(s)</span> }
                      @if (p.high > 0) { <span class="sev" data-severity="HIGH">{{ p.high }} élevée(s)</span> }
                      <span class="muted">{{ p.openFindings }} ouverte(s)</span>
                    </div>
                    <saytu-score-badges [score]="p.score" />
                  </li>
                }
              </ol>
            }
          </section>
        </div>

        <div class="grid">
          <section class="card">
            <h2>Évolution des scores (90 jours)</h2>
            <saytu-trend-chart [points]="d.trend" />
          </section>
          <section class="card">
            <h2>Nouvelles et corrigées par semaine</h2>
            <saytu-flow-chart [flow]="d.weeklyFlow" />
          </section>
        </div>

        <section class="card">
          <h2>Derniers audits</h2>
          <div class="table-wrap">
            <table class="data">
              <thead><tr><th>Date</th><th>Statut</th><th>Périmètre</th><th>Avancement</th><th class="num">Nouvelles</th></tr></thead>
              <tbody>
                @for (r of d.recentRuns; track r.id) {
                  <tr>
                    <td><a routerLink="/audits">{{ r.createdAt | date: 'dd/MM/yyyy HH:mm' }}</a></td>
                    <td><span class="pill" [attr.data-status]="r.status">{{ runStatus(r) }}</span></td>
                    <td>{{ scope(r) }} · {{ r.requestedBy }}</td>
                    <td>{{ progressOf(r) }}</td>
                    <td class="num">{{ r.newFindings }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      }
    } @else if (!error()) {
      <p class="muted">Chargement…</p>
    }
  `,
  styleUrl: '../../shared/page.css',
  styles: `
    .scores { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .score-card { display: flex; flex-direction: column; gap: 2px; }
    .score-card strong { font-size: 2.4rem; line-height: 1.1; font-variant-numeric: tabular-nums; }
    .score-card[data-tone="good"] strong { color: var(--saytu-accent); }
    .score-card[data-tone="fair"] strong { color: var(--saytu-medium); }
    .score-card[data-tone="poor"] strong { color: var(--saytu-critical); }
    .score-card[data-tone="none"] strong { color: var(--saytu-muted); }
    .kpis-card { margin-bottom: 14px; }
    a.kpi { color: inherit; }
    a.kpi strong { color: var(--saytu-accent); }
    .kpi strong.date { font-size: 1.1rem; padding: .3rem 0; }
    .priorities { margin: 0; padding-left: 20px; display: flex; flex-direction: column; gap: 10px; }
    .priorities li { padding-bottom: 8px; border-bottom: 1px solid var(--saytu-border); }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 4px; }
    .name { font-weight: 600; overflow-wrap: anywhere; }
  `,
})
export class DashboardPage implements OnInit {
  private readonly api = inject(InsightsApi);

  readonly data = signal<Dashboard | null>(null);
  readonly error = signal<string | null>(null);
  readonly fmt = formatScore;
  readonly tone = scoreTone;

  ngOnInit(): void {
    this.api.dashboard().subscribe({
      next: d => this.data.set(d),
      error: () => this.error.set('Le tableau de bord n’a pas pu être chargé.'),
    });
  }

  scoreCards(d: Dashboard): { label: string; value: number | null; note: string }[] {
    const g = d.global;
    const note = g ? `couverture ${Math.round(g.coverage)} % · ${RELIABILITY_LABELS[g.reliability]}` : 'pas encore de score';
    return [
      { label: 'Score global', value: g?.global ?? null, note },
      { label: 'Sécurité', value: g?.security ?? null, note: 'Opengrep, Trivy, Gitleaks' },
      { label: 'Qualité', value: g?.quality ?? null, note: 'outils de qualité par langage' },
    ];
  }

  runStatus(r: ScanRun): string {
    return RUN_STATUS_LABELS[r.status] ?? r.status;
  }

  scope(r: ScanRun): string {
    return scopeLabel(r.scope);
  }

  progressOf(r: ScanRun): string {
    return progress(r);
  }
}
