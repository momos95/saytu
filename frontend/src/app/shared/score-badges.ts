import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { RELIABILITY_LABELS, formatScore, scoreTitle, scoreTone } from '../features/audits/audits.logic';
import { ScoreView } from '../features/audits/audits.model';
import { languageLabel } from '../features/repositories/sources.model';

/** Security / quality / global scores with their coverage; "—" when coverage is too low for a score. */
@Component({
  selector: 'saytu-score-badges',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (score(); as s) {
      <span class="scores" [title]="title(s)" data-testid="scores">
        <span class="score" [attr.data-tone]="tone(s.global)"><small>Global</small> {{ fmt(s.global) }}</span>
        <span class="score" [attr.data-tone]="tone(s.security)"><small>Sécurité</small> {{ fmt(s.security) }}</span>
        <span class="score" [attr.data-tone]="tone(s.quality)"><small>Qualité</small> {{ fmt(s.quality) }}</span>
        <span class="coverage" [attr.data-reliability]="s.reliability">couverture {{ round(s.coverage) }} % · {{ reliability(s) }}</span>
      </span>
    } @else {
      <span class="muted small">pas encore de score</span>
    }
  `,
  styles: `
    .scores { display: inline-flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    .score { font-weight: 600; font-size: .85rem; padding: .15rem .5rem; border-radius: 6px; border: 1px solid var(--saytu-border); }
    .score small { font-weight: 400; color: var(--saytu-muted); margin-right: 2px; }
    .score[data-tone="good"] { border-color: var(--saytu-accent); color: var(--saytu-accent); }
    .score[data-tone="fair"] { border-color: var(--saytu-medium); color: var(--saytu-medium); }
    .score[data-tone="poor"] { border-color: var(--saytu-critical); color: var(--saytu-critical); }
    .score[data-tone="none"] { color: var(--saytu-muted); }
    .coverage { font-size: .78rem; color: var(--saytu-muted); }
    .coverage[data-reliability="LOW"], .coverage[data-reliability="INSUFFICIENT"] { color: var(--saytu-medium); }
    .small { font-size: .8rem; }
  `,
})
export class ScoreBadges {
  readonly score = input<ScoreView | null | undefined>(null);

  readonly fmt = formatScore;
  readonly tone = scoreTone;
  readonly title = scoreTitle;

  round(v: number): number {
    return Math.round(v);
  }

  reliability(s: ScoreView): string {
    return RELIABILITY_LABELS[s.reliability];
  }
}

/** Detected languages as small labels. */
@Component({
  selector: 'saytu-language-chips',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @for (l of languages(); track l) {
      <span class="lang" data-testid="language">{{ label(l) }}</span>
    }
  `,
  styles: `
    :host { display: inline-flex; flex-wrap: wrap; gap: 4px; }
    .lang { font-size: .75rem; padding: .1rem .45rem; border-radius: 999px; background: var(--saytu-accent-soft); color: var(--saytu-accent); }
  `,
})
export class LanguageChips {
  readonly languages = input<string[] | null | undefined>([]);
  readonly label = languageLabel;
}
