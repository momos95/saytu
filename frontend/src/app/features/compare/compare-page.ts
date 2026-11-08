import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ScoreBadges } from '../../shared/score-badges';
import { SEVERITY_LABELS, SHORT_SCANNER_LABELS, location, shortSha } from '../audits/audits.logic';
import { Finding } from '../audits/audits.model';
import { InsightsApi } from '../findings/insights.api';
import { Comparison } from '../findings/insights.model';

/** What changed between two analyses of a repository (introduced, fixed, not verifiable). */
@Component({
  selector: 'saytu-compare-page',
  imports: [DatePipe, RouterLink, ScoreBadges],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
    @if (data(); as c) {
      <p class="small"><a [routerLink]="['/repositories', c.head.repositoryId]">← {{ c.head.repository }}</a></p>
      <header class="page-header"><h1>Comparaison d’analyses</h1></header>
      <div class="grid">
        @for (side of [{ label: 'Avant', job: c.base }, { label: 'Après', job: c.head }]; track side.label) {
          <section class="card">
            <h2>{{ side.label }} <span class="muted small">— ⎇ {{ side.job.branch }}</span></h2>
            <p class="small">{{ side.job.finishedAt | date: 'dd/MM/yyyy HH:mm' }} · commit <span class="mono">{{ sha(side.job.commitSha) }}</span>
              · <span class="pill" [attr.data-status]="side.job.status">{{ side.job.status }}</span></p>
            <saytu-score-badges [score]="side.job.score" />
          </section>
        }
      </div>
      <section class="card kpis-card">
        <div class="kpis">
          <div class="kpi" data-testid="introduced"><strong class="bad">{{ c.introducedTotal }}</strong><span>introduites</span></div>
          <div class="kpi" data-testid="fixed"><strong class="good">{{ c.fixedTotal }}</strong><span>corrigées</span></div>
          <div class="kpi"><strong>{{ c.persisting }}</strong><span>toujours présentes</span></div>
          <div class="kpi" data-testid="unverified"><strong class="warn">{{ c.unverifiedTotal }}</strong><span>non vérifiables</span></div>
        </div>
        <p class="small muted">« Non vérifiable » : l’outil concerné n’a pas réussi dans l’une des deux analyses ; son absence ne prouve rien.</p>
      </section>
      @for (block of blocks(c); track block.title) {
        @if (block.items.length) {
          <section class="card">
            <h2>{{ block.title }} <span class="muted small">({{ block.total }})</span></h2>
            <div class="table-wrap"><table class="data">
              <thead><tr><th>Criticité</th><th>Problème</th><th>Emplacement</th><th>Scanner</th></tr></thead>
              <tbody>
                @for (f of block.items; track f.id) {
                  <tr>
                    <td><span class="sev" [attr.data-severity]="f.severity">{{ sevLabel(f.severity) }}</span></td>
                    <td><a [routerLink]="['/findings', f.id]">{{ f.title }}</a><div class="muted small mono">{{ f.ruleId }}</div></td>
                    <td class="mono">{{ where(f) }}</td>
                    <td>{{ scannerLabel(f.scanner) }}</td>
                  </tr>
                }
              </tbody>
            </table></div>
            @if (block.total > block.items.length) { <p class="small muted">{{ block.items.length }} premières affichées.</p> }
          </section>
        }
      }
      <section class="card">
        <h2>Outils</h2>
        <div class="table-wrap"><table class="data">
          <thead><tr><th>Scanner</th><th>Avant</th><th>Après</th></tr></thead>
          <tbody>
            @for (s of c.scanners; track s.scanner) {
              <tr><td>{{ scannerLabel(s.scanner) }}</td>
                <td><span class="pill" [attr.data-status]="s.baseStatus">{{ s.baseStatus ?? '—' }}</span> <span class="small muted">{{ s.baseVersion }}</span></td>
                <td><span class="pill" [attr.data-status]="s.headStatus">{{ s.headStatus ?? '—' }}</span> <span class="small muted">{{ s.headVersion }}</span></td></tr>
            }
          </tbody>
        </table></div>
      </section>
    } @else if (!error()) {
      <p class="muted">Chargement…</p>
    }
  `,
  styleUrl: '../../shared/page.css',
  styles: `
    .kpis-card { margin-bottom: 14px; }
    section.card { margin-bottom: 14px; }
    .grid section.card { margin-bottom: 0; }
    strong.bad { color: var(--saytu-critical); }
    strong.good { color: var(--saytu-accent); }
    strong.warn { color: var(--saytu-medium); }
  `,
})
export class ComparePage implements OnInit {
  private readonly api = inject(InsightsApi);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);

  readonly data = signal<Comparison | null>(null);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    const sub = this.route.queryParams.subscribe(p => {
      const head = typeof p['head'] === 'string' ? p['head'] : null;
      if (!head) {
        this.error.set('Analyse à comparer manquante.');
        return;
      }
      this.data.set(null);
      this.api.compare(head, typeof p['base'] === 'string' ? p['base'] : null).subscribe({
        next: c => this.data.set(c),
        error: (e: { error?: { detail?: string } }) => this.error.set(e?.error?.detail ?? 'Comparaison impossible.'),
      });
    });
    this.destroyRef.onDestroy(() => sub.unsubscribe());
  }

  blocks(c: Comparison): { title: string; items: Finding[]; total: number }[] {
    return [
      { title: 'Introduites', items: c.introduced, total: c.introducedTotal },
      { title: 'Corrigées', items: c.fixed, total: c.fixedTotal },
      { title: 'Non vérifiables', items: c.unverified, total: c.unverifiedTotal },
    ];
  }

  sevLabel(s: string): string {
    return SEVERITY_LABELS[s] ?? s;
  }

  scannerLabel(s: string): string {
    return SHORT_SCANNER_LABELS[s] ?? s;
  }

  where(f: Finding): string {
    return location(f);
  }

  sha(s: string | null): string {
    return s ? shortSha(s) : '—';
  }
}
