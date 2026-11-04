import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Observable } from 'rxjs';
import { ConnectionTestResult } from './connection-test-result';
import { ConnectionsApi, errorMessage } from './connections.api';
import { ConnectionTest, GitConnection, GitConnectionRequest, PROVIDERS, ProviderType, providerInfo } from './connections.model';

/**
 * Create / edit form. The token field is write-only: when editing, leaving it empty keeps the stored
 * token. "Tester" checks the settings typed in the form before anything is saved.
 */
@Component({
  selector: 'saytu-connection-form',
  imports: [ReactiveFormsModule, ConnectionTestResult],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <form [formGroup]="form" (ngSubmit)="save()" class="card" novalidate>
      <h2>{{ existing() ? 'Modifier la connexion' : 'Nouvelle connexion' }}</h2>

      <label>
        Plateforme
        <select formControlName="providerType">
          @for (p of providers; track p.type) {
            <option [value]="p.type">{{ p.label }}</option>
          }
        </select>
      </label>
      <p class="help">{{ info().help }}</p>

      <label>
        Nom
        <input formControlName="name" maxlength="120" autocomplete="off" />
        @if (form.controls.name.touched && form.controls.name.invalid) {
          <span class="field-error">Nom obligatoire (lettres, chiffres, espaces, . _ - ( ) uniquement).</span>
        }
      </label>

      <label>
        {{ info().type === 'LOCAL' ? 'Répertoire' : 'URL' }}
        <input formControlName="baseUrl" [placeholder]="info().urlPlaceholder" inputmode="url" autocomplete="off" />
      </label>

      @if (info().usesToken) {
        @if (info().usernameLabel; as usernameLabel) {
          <label>
            {{ usernameLabel }}
            <input formControlName="username" autocomplete="off" />
          </label>
        }
        <label>
          Token
          <input formControlName="token" type="password" autocomplete="new-password"
                 [placeholder]="existing()?.hasToken ? 'Laisser vide pour conserver le token enregistré' : 'Vide = accès anonyme (dépôts publics)'" />
        </label>
        @if (existing()?.hasToken) {
          <label class="inline">
            <input type="checkbox" formControlName="clearToken" /> Supprimer le token enregistré
          </label>
        }
        <details>
          <summary>Options avancées</summary>
          <label>
            URL de l’API (si elle n’est pas à l’emplacement standard)
            <input formControlName="apiUrl" inputmode="url" autocomplete="off" />
          </label>
        </details>
      }

      <label class="inline">
        <input type="checkbox" formControlName="enabled" /> Connexion active
      </label>

      @if (error()) {
        <p class="field-error" role="alert">{{ error() }}</p>
      }
      @if (testResult(); as r) {
        <saytu-connection-test-result [result]="r" />
      }

      <div class="actions">
        <button type="button" (click)="cancelled.emit()">Annuler</button>
        <button type="button" (click)="test()" [disabled]="busy() || form.invalid">Tester</button>
        <button type="submit" class="primary" [disabled]="busy() || form.invalid">Enregistrer</button>
      </div>
    </form>
  `,
  styles: `
    form { display: flex; flex-direction: column; gap: 12px; }
    h2 { margin: 0; font-size: 1.15rem; }
    label { display: flex; flex-direction: column; gap: 4px; font-weight: 500; font-size: .9rem; }
    label.inline { flex-direction: row; align-items: center; gap: 8px; font-weight: 400; }
    input:not([type=checkbox]), select { font: inherit; padding: .5rem .6rem; border-radius: 6px; border: 1px solid var(--saytu-border);
                     background: var(--saytu-bg); color: var(--saytu-text); }
    .help { margin: -4px 0 0; font-size: .85rem; color: var(--saytu-muted); }
    .field-error { color: var(--saytu-critical); font-size: .85rem; font-weight: 400; }
    details summary { cursor: pointer; font-size: .9rem; color: var(--saytu-muted); }
    details label { margin-top: 8px; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
    button { font: inherit; padding: .5rem .9rem; border-radius: 6px; border: 1px solid var(--saytu-border);
             background: var(--saytu-surface); color: var(--saytu-text); cursor: pointer; }
    button.primary { background: var(--saytu-accent); border-color: var(--saytu-accent); color: #fff; }
    button:disabled { opacity: .6; cursor: not-allowed; }
  `,
})
export class ConnectionForm {
  private readonly api = inject(ConnectionsApi);
  private readonly fb = inject(NonNullableFormBuilder);

  /** Connection to edit; undefined to create one. */
  readonly existing = input<GitConnection>();
  readonly saved = output<GitConnection>();
  readonly cancelled = output<void>();

  readonly providers = PROVIDERS;
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly testResult = signal<ConnectionTest | null>(null);

  readonly form = this.fb.group({
    providerType: this.fb.control<ProviderType>('GITLAB'),
    name: this.fb.control('', [Validators.required, Validators.maxLength(120), Validators.pattern(/^[\p{L}\p{N} ._()-]+$/u)]),
    baseUrl: this.fb.control(''),
    apiUrl: this.fb.control(''),
    username: this.fb.control(''),
    token: this.fb.control(''),
    clearToken: this.fb.control(false),
    enabled: this.fb.control(true),
  });

  private readonly providerType = toSignal(this.form.controls.providerType.valueChanges, {
    initialValue: this.form.controls.providerType.value,
  });
  readonly info = computed(() => providerInfo(this.providerType()));

  constructor() {
    effect(() => {
      const c = this.existing();
      // The platform of a saved connection cannot change (the API refuses it).
      if (c) {
        this.form.controls.providerType.disable();
      } else {
        this.form.controls.providerType.enable();
      }
      if (c) {
        this.form.reset({
          providerType: c.providerType,
          name: c.name,
          baseUrl: c.baseUrl.startsWith('file://') ? c.baseUrl.substring('file://'.length) : c.baseUrl,
          apiUrl: c.apiUrl ?? '',
          username: c.username ?? '',
          token: '',
          clearToken: false,
          enabled: c.enabled,
        });
      }
      this.testResult.set(null);
    });
  }

  request(): GitConnectionRequest {
    const v = this.form.getRawValue();
    const info = providerInfo(v.providerType);
    return {
      name: v.name.trim(),
      providerType: v.providerType,
      baseUrl: v.baseUrl.trim() || null,
      apiUrl: info.usesToken ? v.apiUrl.trim() || null : null,
      username: info.usesToken && info.usernameLabel ? v.username.trim() || null : null,
      token: info.usesToken ? v.token || null : null,
      clearToken: v.clearToken,
      enabled: v.enabled,
      version: this.existing()?.version ?? null,
    };
  }

  test(): void {
    const existing = this.existing();
    const request = this.request();
    this.run(
      // A saved connection whose form was not touched is tested with its stored token.
      existing && !this.form.dirty ? this.api.test(existing.id) : this.api.testDraft(request),
      r => this.testResult.set(r),
    );
  }

  save(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const existing = this.existing();
    const request = this.request();
    this.run(existing ? this.api.update(existing.id, request) : this.api.create(request), c => {
      this.form.controls.token.reset('');
      this.saved.emit(c);
    });
  }

  private run<T>(call: Observable<T>, onSuccess: (value: T) => void): void {
    this.busy.set(true);
    this.error.set(null);
    call.subscribe({
      next: value => {
        this.busy.set(false);
        onSuccess(value);
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.error.set(errorMessage(e));
      },
    });
  }
}
