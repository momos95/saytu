import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { errorMessage } from '../connections/connections.api';
import { SourcesApi } from '../repositories/sources.api';
import { branchProblem, parseBranchList } from '../repositories/sources.logic';
import { RemoteBranch, Repository } from '../repositories/sources.model';

/** Custom branch list of one repository: pick from the platform's branches or type names. */
@Component({
  selector: 'saytu-branch-picker',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="picker">
      <p class="muted">Branches à auditer pour <strong>{{ repository().fullName }}</strong></p>
      @if (loading()) {
        <p class="muted">Lecture des branches sur la plateforme…</p>
      } @else if (remote().length) {
        <ul class="remote">
          @for (b of remote(); track b.name) {
            <li>
              <label>
                <input type="checkbox" [checked]="chosen().has(b.name)" (change)="toggle(b.name, $any($event.target).checked)" />
                {{ b.name }}
                @if (b.isDefault) { <span class="tag">par défaut</span> }
                @if (b.isProtected) { <span class="tag">protégée</span> }
              </label>
            </li>
          }
        </ul>
      }
      @if (remoteError()) {
        <p class="warn">{{ remoteError() }}</p>
      }
      <label class="typed">
        Autres branches (séparées par des virgules ou des espaces)
        <input [value]="typed()" (input)="typed.set($any($event.target).value)" placeholder="release/2026.12, hotfix" />
      </label>
      @for (p of problems(); track p) {
        <p class="error">{{ p }}</p>
      }
      @if (saveError()) {
        <p class="error" role="alert">{{ saveError() }}</p>
      }
      <div class="actions">
        <span class="muted">{{ selection().length }} branche(s)</span>
        <button type="button" (click)="cancelled.emit()">Annuler</button>
        <button type="button" class="primary" (click)="save()" [disabled]="saving() || !selection().length || problems().length > 0">
          Enregistrer
        </button>
      </div>
    </div>
  `,
  styles: `
    .picker { border: 1px solid var(--saytu-border); border-radius: 8px; padding: 12px; margin-top: 8px; background: var(--saytu-bg); }
    .remote { list-style: none; margin: 0; padding: 0; max-height: 240px; overflow: auto; }
    .remote li { padding: 3px 0; }
    label { display: flex; gap: 6px; align-items: center; font-size: .9rem; overflow-wrap: anywhere; }
    .typed { flex-direction: column; align-items: stretch; margin-top: 10px; }
    input:not([type=checkbox]) { font: inherit; padding: .45rem .6rem; border-radius: 6px; border: 1px solid var(--saytu-border);
                                 background: var(--saytu-surface); color: var(--saytu-text); }
    .tag { font-size: .7rem; padding: 0 .4rem; border-radius: 999px; background: var(--saytu-hover); }
    .actions { display: flex; gap: 8px; align-items: center; justify-content: flex-end; margin-top: 10px; flex-wrap: wrap; }
    .error { color: var(--saytu-critical); font-size: .85rem; margin: 4px 0 0; }
    .warn { color: var(--saytu-medium); font-size: .85rem; }
    button { font: inherit; font-size: .9rem; padding: .4rem .8rem; border-radius: 6px; border: 1px solid var(--saytu-border);
             background: var(--saytu-surface); color: var(--saytu-text); cursor: pointer; }
    button.primary { background: var(--saytu-accent); border-color: var(--saytu-accent); color: #fff; }
    button:disabled { opacity: .6; }
  `,
})
export class BranchPicker implements OnInit {
  private readonly api = inject(SourcesApi);

  readonly repository = input.required<Repository>();
  readonly saved = output<Repository>();
  readonly cancelled = output<void>();

  readonly remote = signal<RemoteBranch[]>([]);
  readonly loading = signal(true);
  readonly remoteError = signal<string | null>(null);
  readonly chosen = signal<Set<string>>(new Set());
  readonly typed = signal('');
  readonly saving = signal(false);
  readonly saveError = signal<string | null>(null);

  /** Checked remote branches plus typed names, without duplicates. */
  readonly selection = computed(() => {
    const all = [...this.chosen(), ...parseBranchList(this.typed())];
    return [...new Set(all)];
  });
  readonly problems = computed(() => parseBranchList(this.typed())
    .map(name => [name, branchProblem(name)] as const)
    .filter(([, p]) => p !== null)
    .map(([name, p]) => `« ${name} » : ${p}`));

  ngOnInit(): void {
    const current = this.repository().branches;
    this.chosen.set(new Set(current));
    this.api.remoteBranches(this.repository().id).subscribe({
      next: r => {
        this.remote.set(r.branches);
        // configured branches that no longer exist remotely stay editable as typed text
        const remoteNames = new Set(r.branches.map(b => b.name));
        this.typed.set(current.filter(n => !remoteNames.has(n)).join(', '));
        this.chosen.set(new Set(current.filter(n => remoteNames.has(n))));
        if (r.status !== 'OK') {
          this.remoteError.set(r.message ?? `Liste incomplète (${r.status}).`);
        }
        this.loading.set(false);
      },
      error: e => {
        this.remoteError.set(`Branches de la plateforme indisponibles : ${errorMessage(e)} Vous pouvez les saisir.`);
        this.typed.set(current.join(', '));
        this.chosen.set(new Set());
        this.loading.set(false);
      },
    });
  }

  toggle(name: string, checked: boolean): void {
    this.chosen.update(s => {
      const next = new Set(s);
      if (checked) {
        next.add(name);
      } else {
        next.delete(name);
      }
      return next;
    });
  }

  save(): void {
    this.saving.set(true);
    this.saveError.set(null);
    this.api.setCustomBranches(this.repository().id, this.selection()).subscribe({
      next: r => {
        this.saving.set(false);
        this.saved.emit(r);
      },
      error: e => {
        this.saving.set(false);
        this.saveError.set(errorMessage(e));
      },
    });
  }
}
