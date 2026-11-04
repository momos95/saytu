import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute } from '@angular/router';
import { map } from 'rxjs';

export interface PlannedPageData {
  title: string;
  /** Development phase that delivers the page */
  phase: number;
  summary: string;
}

/**
 * Placeholder for a page that is routed but not implemented yet. It says so explicitly:
 * the UI never shows invented data.
 */
@Component({
  selector: 'saytu-planned-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (page(); as p) {
      <header class="page-header">
        <h1>{{ p.title }}</h1>
        <span class="badge" data-testid="phase-badge">Phase {{ p.phase }}</span>
      </header>
      <section class="card">
        <p>{{ p.summary }}</p>
        <p class="muted" role="status">
          Page non implémentée : elle sera livrée en phase {{ p.phase }}. Aucune donnée n’est affichée tant
          que les analyses réelles ne sont pas disponibles.
        </p>
      </section>
    }
  `,
  styles: `
    .page-header { display: flex; align-items: center; gap: .75rem; margin-bottom: 1rem; }
    h1 { margin: 0; font-size: 1.5rem; }
    .badge { background: var(--saytu-accent-soft); color: var(--saytu-accent); border-radius: 999px;
             padding: .15rem .6rem; font-size: .8rem; font-weight: 600; }
  `,
})
export class PlannedPage {
  private readonly route = inject(ActivatedRoute);
  readonly page = toSignal(this.route.data.pipe(map(d => d as PlannedPageData)));
}
