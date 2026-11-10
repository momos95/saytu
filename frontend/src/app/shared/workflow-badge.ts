import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { WORKFLOW_LABELS, WorkflowStatus } from '../features/findings/insights.logic';

/** Result of the Git workflow check (main/master on the latest tag, develop branch) as a small chip. */
@Component({
  selector: 'saytu-workflow-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (status(); as s) {
      <span class="wf" [attr.data-status]="s" [title]="title()" data-testid="workflow-badge">branches : {{ label() }}</span>
    }
  `,
  styles: `
    .wf { font-size: .75rem; padding: .1rem .45rem; border-radius: 999px; border: 1px solid var(--saytu-border); white-space: nowrap; }
    .wf[data-status="PASS"] { border-color: var(--saytu-accent); color: var(--saytu-accent); }
    .wf[data-status="WARN"] { border-color: var(--saytu-medium); color: var(--saytu-medium); }
    .wf[data-status="FAIL"] { border-color: var(--saytu-critical); color: var(--saytu-critical); }
  `,
})
export class WorkflowBadge {
  readonly status = input<WorkflowStatus | null | undefined>(null);
  readonly label = computed(() => { const s = this.status(); return s ? WORKFLOW_LABELS[s] : ''; });
  readonly title = computed(() =>
    'Organisation des branches : main ou master sur le dernier tag de version, branche develop de travail');
}
