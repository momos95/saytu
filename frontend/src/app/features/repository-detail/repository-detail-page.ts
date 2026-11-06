import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { FlowChart, SeverityBreakdown, TrendChart } from '../../shared/charts';
import { ReportDownload } from '../../shared/report-download';
import { LanguageChips, ScoreBadges } from '../../shared/score-badges';
import { AuditsApi } from '../audits/audits.api';
import { RUN_STATUS_LABELS, SEVERITY_LABELS, SHORT_SCANNER_LABELS, shortSha } from '../audits/audits.logic';
import { RunStatus } from '../audits/audits.model';
import { InsightsApi } from '../findings/insights.api';
import { SEVERITIES } from '../findings/insights.logic';
import { RepositoryOverview } from '../findings/insights.model';

const PROVIDERS: Record<string, string> = {
  GITLAB: 'GitLab', GITHUB: 'GitHub', BITBUCKET_CLOUD: 'Bitbucket Cloud', BITBUCKET_DATA_CENTER: 'Bitbucket Data Center', LOCAL: 'Dépôt local',
};

/** Everything about one repository: scores per branch, trend, open findings, frequent rules, recent jobs. */
@Component({
  selector: 'saytu-repository-detail-page',
  imports: [DatePipe, RouterLink, ScoreBadges, LanguageChips, TrendChart, FlowChart, SeverityBreakdown, ReportDownload],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p class="small"><a routerLink="/repositories">← Organisations &amp; dépôts</a></p>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
    @if (data(); as d) {
      <header class="page-header">
        <div>
          <h1>{{ d.repository.fullName }}</h1>
          <p class="small muted sub">
            {{ provider(d.repository.providerType) }} · {{ d.repository.connectionName }}
            @if (d.repository.namespace) { · {{ d.repository.namespace }} }
            @if (d.repository.defaultBranch) { · branche par défaut {{ d.repository.defaultBranch }} }
            @if (d.repository.webUrl) { · <a [href]="d.repository.webUrl" target="_blank" rel="noopener noreferrer">ouvrir sur la plateforme</a> }
            @if (d.repository.archived) { <span class="pill">archivé</span> }
            @if (d.repository.removed) { <span class="pill" data-status="FAILED">n’existe plus sur la plateforme</span> }
          </p>
          <saytu-language-chips [languages]="d.repository.languages" />
        </div>
        <div class="actions">
          @if (canAudit() && !d.repository.removed) {
            <button type="button" class="primary" (click)="audit()" [disabled]="busy()">Auditer ce dépôt</button>
          }
          <saytu-report-download [filters]="{ repositoryId: d.repository.id }" />
        </div>
      </header>
      @if (auditError()) { <p class="error" role="alert">{{ auditError() }}</p> }

      <section class="card score-line">
        <span class="muted small">Score du dépôt (branche la plus faible)</span>
        <saytu-score-badges [score]="d.score" />
      </section>

      <section class="card">
        <h2>Branches</h2>
        @if (d.branches.length === 0) {
          <p class="empty">Aucune branche analysée. Lancez un audit pour obtenir des résultats.</p>
        } @else {
          <div class="table-wrap"><table class="data">
            <thead><tr><th>Branche</th><th>Score</th>@for (s of severities; track s) { <th class="num">{{ sevLabel(s) }}</th> }<th></th></tr></thead>
            <tbody>
              @for (b of d.branches; track b.branch) {
                <tr data-testid="branch">
                  <td class="name">{{ b.branch }}</td>
                  <td><saytu-score-badges [score]="b.score" /></td>
                  @for (s of severities; track s) {
                    <td class="num">@if (b.openBySeverity[s] > 0) { <span class="sev" [attr.data-severity]="s">{{ b.openBySeverity[s] }}</span> } @else { <span class="muted">0</span> }</td>
                  }
                  <td><a routerLink="/findings" [queryParams]="{ repositoryId: d.repository.id, branch: b.branch, status: 'OPEN' }">voir</a></td>
                </tr>
              }
            </tbody>
          </table></div>
        }
      </section>

      <div class="grid">
        <section class="card">
          <h2>Vulnérabilités ouvertes</h2>
          <saytu-severity-breakdown [counts]="d.openBySeverity" [repositoryId]="d.repository.id" />
        </section>
        <section class="card">
          <h2>Règles les plus fréquentes</h2>
          @if (d.topRules.length === 0) {
            <p class="empty">Aucune vulnérabilité ouverte.</p>
          } @else {
            <div class="table-wrap"><table class="data">
              <thead><tr><th>Règle</th><th class="num">Ouvertes</th></tr></thead>
              <tbody>
                @for (r of d.topRules; track r.scanner + r.ruleId) {
                  <tr>
                    <td><span class="sev" [attr.data-severity]="r.severity">{{ sevLabel(r.severity) }}</span>
                      <a routerLink="/findings" [queryParams]="{ repositoryId: d.repository.id, q: r.ruleId, status: 'OPEN' }">{{ r.title }}</a>
                      <div class="mono muted">{{ scannerLabel(r.scanner) }} · {{ r.ruleId }}</div></td>
                    <td class="num">{{ r.count }}</td>
                  </tr>
                }
              </tbody>
            </table></div>
          }
        </section>
      </div>

      <div class="grid">
        <section class="card"><h2>Évolution du score (90 jours)</h2><saytu-trend-chart [points]="d.trend" /></section>
        <section class="card"><h2>Nouvelles et corrigées par semaine</h2><saytu-flow-chart [flow]="d.weeklyFlow" /></section>
      </div>

      <section class="card">
        <h2>Derniers audits du dépôt</h2>
        @if (d.recentJobs.length === 0) {
          <p class="empty">Jamais audité.</p>
        } @else {
          <div class="table-wrap"><table class="data">
            <thead><tr><th>Date</th><th>Branche</th><th>Statut</th><th>Commit</th><th class="num">Résultats</th><th class="num">Nouveaux</th><th class="num">Corrigés</th></tr></thead>
            <tbody>
              @for (j of d.recentJobs; track j.id) {
                <tr>
                  <td class="small">{{ (j.finishedAt ?? j.queuedAt) | date: 'dd/MM/yyyy HH:mm' }}</td>
                  <td>{{ j.branch }}</td>
                  <td><span class="pill" [attr.data-status]="j.status" [title]="j.errorMessage ?? ''">{{ runStatus(j.status) }}</span></td>
                  <td class="mono">{{ sha(j.commitSha) }}</td>
                  <td class="num">{{ j.findings }}</td><td class="num">{{ j.newFindings }}</td><td class="num">{{ j.resolvedFindings }}</td>
                </tr>
              }
            </tbody>
          </table></div>
        }
      </section>
    } @else if (!error()) {
      <p class="muted">Chargement…</p>
    }
  `,
  styleUrl: '../../shared/page.css',
  styles: `
    .page-header { align-items: flex-start; }
    .sub { margin: 4px 0 8px; display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
    .actions { display: flex; flex-direction: column; gap: 8px; align-items: flex-end; }
    .score-line { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 14px; }
    .name { font-weight: 600; overflow-wrap: anywhere; }
    section.card { margin-bottom: 14px; }
    .grid section.card { margin-bottom: 0; }
    @media (max-width: 640px) { .actions { align-items: flex-start; } }
  `,
})
export class RepositoryDetailPage implements OnInit {
  private readonly api = inject(InsightsApi);
  private readonly audits = inject(AuditsApi);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  readonly id = input.required<string>();
  readonly data = signal<RepositoryOverview | null>(null);
  readonly error = signal<string | null>(null);
  readonly auditError = signal<string | null>(null);
  readonly busy = signal(false);
  readonly severities = SEVERITIES;
  readonly canAudit = computed(() => this.auth.hasRole('AUDITOR') || this.auth.hasRole('ADMIN'));

  ngOnInit(): void {
    this.api.repository(this.id()).subscribe({
      next: d => this.data.set(d),
      error: () => this.error.set('Dépôt introuvable.'),
    });
  }

  audit(): void {
    this.busy.set(true);
    this.auditError.set(null);
    this.audits.request({ allTargets: false, repositoryIds: [this.id()] }).subscribe({
      next: () => this.router.navigate(['/audits']),
      error: () => {
        this.busy.set(false);
        this.auditError.set('L’audit n’a pas pu être lancé.');
      },
    });
  }

  provider(p: string): string {
    return PROVIDERS[p] ?? p;
  }

  sevLabel(s: string): string {
    return SEVERITY_LABELS[s] ?? s;
  }

  scannerLabel(s: string): string {
    return SHORT_SCANNER_LABELS[s] ?? s;
  }

  runStatus(s: string): string {
    return RUN_STATUS_LABELS[s as RunStatus] ?? s;
  }

  sha(s: string | null): string {
    return s ? shortSha(s) : '—';
  }
}
