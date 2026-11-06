import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import { InsightsApi } from '../features/findings/insights.api';
import { FindingFilters, ReportFormat } from '../features/findings/insights.model';

/** Buttons that generate a report on the server for the given filters and save it as a file. */
@Component({
  selector: 'saytu-report-download',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="reports" role="group" aria-label="Rapports">
      <span class="label">Rapport</span>
      @for (f of formats; track f.id) {
        <button type="button" (click)="download(f.id)" [disabled]="busy() !== null" [title]="f.title" [attr.data-format]="f.id">
          {{ busy() === f.id ? '…' : f.label }}
        </button>
      }
    </div>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
  `,
  styles: `
    .reports { display: inline-flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    .label { font-size: .8rem; color: var(--saytu-muted); margin-right: 2px; }
    button { font: inherit; font-size: .8rem; padding: .3rem .6rem; border-radius: 6px; border: 1px solid var(--saytu-border);
             background: var(--saytu-surface); color: var(--saytu-text); cursor: pointer; }
    button:disabled { opacity: .6; }
    .error { color: var(--saytu-critical); font-size: .82rem; margin: 4px 0 0; }
  `,
})
export class ReportDownload {
  private readonly api = inject(InsightsApi);

  readonly filters = input<FindingFilters>({});
  readonly busy = signal<ReportFormat | null>(null);
  readonly error = signal<string | null>(null);
  readonly formats: { id: ReportFormat; label: string; title: string }[] = [
    { id: 'pdf', label: 'PDF', title: 'Rapport imprimable (2 000 vulnérabilités détaillées au plus)' },
    { id: 'html', label: 'HTML', title: 'Page autonome, lisible hors ligne' },
    { id: 'json', label: 'JSON', title: 'Export complet (format saytu-report/1)' },
    { id: 'sarif', label: 'SARIF', title: 'SARIF 2.1.0 pour les outils compatibles (IDE, forges)' },
  ];

  download(format: ReportFormat): void {
    this.busy.set(format);
    this.error.set(null);
    this.api.report(format, this.filters()).subscribe({
      next: r => {
        this.busy.set(null);
        const url = URL.createObjectURL(r.blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = r.fileName;
        a.rel = 'noopener';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      },
      error: () => {
        this.busy.set(null);
        this.error.set('Le rapport n’a pas pu être généré.');
      },
    });
  }
}
