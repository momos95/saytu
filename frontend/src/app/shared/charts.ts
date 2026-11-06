import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { Severity } from '../features/audits/audits.model';
import { SEVERITY_LABELS } from '../features/audits/audits.logic';
import { SEVERITIES, TYPE_LABELS, TYPES, flowBars, severityTotals, shares, trendSeries } from '../features/findings/insights.logic';
import { FlowPoint, SeverityTypeCounts, TrendPoint } from '../features/findings/insights.model';

/** Score trend (global, security, quality) over the last days; gaps where no score could be computed. */
@Component({
  selector: 'saytu-trend-chart',
  imports: [DatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (points().length === 0) {
      <p class="empty">Pas encore d’historique de score : il se construit à chaque audit terminé.</p>
    } @else {
      <svg [attr.viewBox]="'-30 -8 ' + (width + 40) + ' ' + (height + 30)" role="img" class="chart"
           [attr.aria-label]="'Évolution des scores sur ' + points().length + ' jour(s)'">
        @for (y of [0, 50, 100]; track y) {
          <line [attr.x1]="0" [attr.x2]="width" [attr.y1]="height - y * height / 100" [attr.y2]="height - y * height / 100" class="grid" />
          <text [attr.x]="-6" [attr.y]="height - y * height / 100 + 4" class="axis" text-anchor="end">{{ y }}</text>
        }
        @for (s of series(); track s.key) {
          @for (seg of s.segments; track $index) {
            @if (seg.includes(' ')) {
              <polyline [attr.points]="seg" class="line" [attr.data-series]="s.key" />
            } @else {
              <circle [attr.cx]="seg.split(',')[0]" [attr.cy]="seg.split(',')[1]" r="3" class="dot" [attr.data-series]="s.key" />
            }
          }
        }
        <text [attr.x]="0" [attr.y]="height + 18" class="axis">{{ points()[0].day | date: 'dd/MM' }}</text>
        <text [attr.x]="width" [attr.y]="height + 18" class="axis" text-anchor="end">{{ points()[points().length - 1].day | date: 'dd/MM' }}</text>
      </svg>
      <div class="legend">
        @for (s of series(); track s.key) { <span [attr.data-series]="s.key">{{ s.label }}</span> }
        <span class="muted">· trou dans la courbe = couverture insuffisante ce jour-là</span>
      </div>
    }
  `,
  styles: `
    .chart { width: 100%; height: auto; max-height: 240px; display: block; }
    .grid { stroke: var(--saytu-border); stroke-width: 1; }
    .axis { fill: var(--saytu-muted); font-size: 10px; }
    .line { fill: none; stroke-width: 2.2; stroke-linejoin: round; stroke-linecap: round; }
    .line[data-series="global"], .dot[data-series="global"] { stroke: var(--saytu-accent); fill: var(--saytu-accent); }
    .line[data-series="security"], .dot[data-series="security"] { stroke: var(--saytu-high); fill: var(--saytu-high); }
    .line[data-series="quality"], .dot[data-series="quality"] { stroke: var(--saytu-low); fill: var(--saytu-low); }
    .line { fill: none !important; }
    .legend { display: flex; flex-wrap: wrap; gap: 12px; font-size: .78rem; margin-top: 6px; }
    .legend span[data-series]::before { content: ''; display: inline-block; width: 14px; height: 3px; margin-right: 5px; vertical-align: middle; border-radius: 2px; }
    .legend span[data-series="global"]::before { background: var(--saytu-accent); }
    .legend span[data-series="security"]::before { background: var(--saytu-high); }
    .legend span[data-series="quality"]::before { background: var(--saytu-low); }
    .muted, .empty { color: var(--saytu-muted); }
    .empty { margin: 0; font-size: .88rem; }
  `,
})
export class TrendChart {
  readonly points = input<TrendPoint[]>([]);
  readonly width = 600;
  readonly height = 160;
  readonly series = computed(() => trendSeries(this.points(), this.width, this.height));
}

/** Findings that appeared and were fixed, per week (12 weeks). */
@Component({
  selector: 'saytu-flow-chart',
  imports: [DatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="bars" role="img" [attr.aria-label]="'Nouvelles et corrigées par semaine'">
      @for (b of bars(); track b.week) {
        <div class="week" [title]="'Semaine du ' + (b.week | date: 'dd/MM') + ' : ' + b.opened + ' nouvelle(s), ' + b.resolved + ' corrigée(s)'">
          <div class="pair">
            <span class="bar opened" [style.height.px]="b.openedH"></span>
            <span class="bar resolved" [style.height.px]="b.resolvedH"></span>
          </div>
          <span class="label">{{ b.week | date: 'dd/MM' }}</span>
        </div>
      }
    </div>
    <div class="legend"><span class="opened">nouvelles</span><span class="resolved">corrigées</span></div>
  `,
  styles: `
    .bars { display: flex; align-items: flex-end; gap: 4px; height: 110px; overflow-x: auto; }
    .week { flex: 1 0 22px; display: flex; flex-direction: column; align-items: center; gap: 4px; }
    .pair { display: flex; align-items: flex-end; gap: 2px; height: 80px; }
    .bar { width: 7px; border-radius: 2px 2px 0 0; min-height: 0; }
    .bar.opened, .legend .opened::before { background: var(--saytu-high); }
    .bar.resolved, .legend .resolved::before { background: var(--saytu-accent); }
    .label { font-size: 9px; color: var(--saytu-muted); }
    .legend { display: flex; gap: 12px; font-size: .78rem; margin-top: 6px; }
    .legend span::before { content: ''; display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; }
  `,
})
export class FlowChart {
  readonly flow = input<FlowPoint[]>([]);
  readonly bars = computed(() => flowBars(this.flow(), 80));
}

/** Open findings per severity (stacked bar) and per severity × type (table); every number links to the list. */
@Component({
  selector: 'saytu-severity-breakdown',
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (totals().total === 0) {
      <p class="empty">Aucune vulnérabilité ouverte.</p>
    } @else {
      <div class="stacked" role="img" [attr.aria-label]="totals().total + ' vulnérabilités ouvertes'">
        @for (s of severities; track s; let i = $index) {
          @if (widths()[i] > 0) {
            <span [attr.data-severity]="s" [style.width.%]="widths()[i]" [title]="label(s) + ' : ' + totals().bySeverity[s]"></span>
          }
        }
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr><th>Criticité</th>@for (t of types; track t) { <th class="num">{{ typeLabel(t) }}</th> }<th class="num">Total</th></tr></thead>
          <tbody>
            @for (s of severities; track s) {
              <tr>
                <td><span class="sev" [attr.data-severity]="s">{{ label(s) }}</span></td>
                @for (t of types; track t) {
                  <td class="num">
                    @if (counts()![s][t] > 0) {
                      <a routerLink="/findings" [queryParams]="params(s, t)">{{ counts()![s][t] }}</a>
                    } @else { <span class="muted">0</span> }
                  </td>
                }
                <td class="num"><a routerLink="/findings" [queryParams]="params(s, null)">{{ totals().bySeverity[s] }}</a></td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    }
  `,
  styleUrl: './page.css',
  styles: `
    .stacked { display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: var(--saytu-hover); margin-bottom: 12px; }
    .stacked span[data-severity="CRITICAL"] { background: var(--saytu-critical); }
    .stacked span[data-severity="HIGH"] { background: var(--saytu-high); }
    .stacked span[data-severity="MEDIUM"] { background: var(--saytu-medium); }
    .stacked span[data-severity="LOW"] { background: var(--saytu-low); }
    .stacked span[data-severity="INFO"] { background: var(--saytu-info); }
  `,
})
export class SeverityBreakdown {
  readonly counts = input<SeverityTypeCounts | null>(null);
  readonly repositoryId = input<string | null>(null);
  readonly severities = SEVERITIES;
  readonly types = TYPES;
  readonly totals = computed(() => severityTotals(this.counts()));
  readonly widths = computed(() => shares(SEVERITIES.map(s => this.totals().bySeverity[s])));

  label(s: Severity): string {
    return SEVERITY_LABELS[s] ?? s;
  }

  typeLabel(t: string): string {
    return TYPE_LABELS[t] ?? t;
  }

  params(severity: string, type: string | null): Record<string, string> {
    const p: Record<string, string> = { status: 'OPEN', severity };
    if (type) {
      p['type'] = type;
    }
    const repo = this.repositoryId();
    if (repo) {
      p['repositoryId'] = repo;
    }
    return p;
  }
}
