import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService } from '../../core/auth/auth.service';
import { SourcesApi } from '../repositories/sources.api';
import { Repository } from '../repositories/sources.model';
import { CRON_PRESETS, DELIVERY_LABELS, ROLE_LABELS, describeCron, randomSecret } from './settings.logic';
import { SettingsApi } from './settings.api';
import { AiSettings, AiTest, AppUser, Credentials, Delivery, Schedule, ScheduleScope, TestResult, UserStatus, Webhook } from './settings.model';

type Tab = 'schedules' | 'webhooks' | 'users' | 'ai';

interface ScheduleForm {
  id: string | null;
  name: string;
  cronExpression: string;
  timeZone: string;
  scope: ScheduleScope;
  enabled: boolean;
  repositoryIds: string[];
}

interface WebhookForm {
  id: string | null;
  name: string;
  url: string;
  format: 'GENERIC' | 'SLACK';
  minSeverity: string;
  events: string[];
  enabled: boolean;
  secret: string;
  changeSecret: boolean;
}

function problem(e: unknown, fallback: string): string {
  const err = e as { error?: { detail?: string }; status?: number };
  return err?.error?.detail ?? (err?.status === 403 ? 'Réservé aux administrateurs.' : fallback);
}

/** Schedules, webhook alerts, users and local AI. Everything is read-only for non-administrators. */
@Component({
  selector: 'saytu-settings-page',
  imports: [DatePipe, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="page-header"><h1>Utilisateurs &amp; paramètres</h1></header>
    <nav class="tabs" role="tablist">
      @for (t of tabs; track t.id) {
        <button type="button" role="tab" [attr.aria-selected]="tab() === t.id" (click)="open(t.id)" [attr.data-tab]="t.id">{{ t.label }}</button>
      }
    </nav>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }

    @switch (tab()) {
      @case ('schedules') {
        <section class="card">
          <h2>Audits planifiés</h2>
          @if (schedules().length === 0) {
            <p class="empty">Aucune planification : les audits ne partent qu’à la main.</p>
          } @else {
            <div class="table-wrap"><table class="data">
              <thead><tr><th>Nom</th><th>Quand</th><th>Périmètre</th><th>Prochain</th><th>Dernier déclenchement</th><th></th></tr></thead>
              <tbody>
                @for (s of schedules(); track s.id) {
                  <tr data-testid="schedule">
                    <td><strong>{{ s.name }}</strong> @if (!s.enabled) { <span class="pill">désactivée</span> }</td>
                    <td>{{ cronLabel(s.cronExpression) }}<div class="mono muted">{{ s.cronExpression }} · {{ s.timeZone }}</div></td>
                    <td>{{ s.scope === 'ALL_SELECTED' ? 'tous les dépôts sélectionnés' : s.repositoryIds.length + s.namespaceIds.length + ' cible(s)' }}</td>
                    <td class="small">{{ s.nextFireAt ? (s.nextFireAt | date: 'dd/MM/yyyy HH:mm') : '—' }}</td>
                    <td class="small">
                      @if (s.lastFiredAt) { {{ s.lastFiredAt | date: 'dd/MM HH:mm' }} : {{ s.lastOutcome }}
                        @if (s.lastRunStatus) { <span class="pill" [attr.data-status]="s.lastRunStatus">{{ s.lastRunStatus }}</span> } }
                      @else { jamais }
                    </td>
                    <td class="actions">
                      @if (isAdmin()) {
                        <button type="button" (click)="editSchedule(s)">Modifier</button>
                        <button type="button" class="danger" (click)="deleteSchedule(s)">Supprimer</button>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table></div>
          }
          <p class="small muted">Un déclenchement crée un audit ordinaire (visible dans <a routerLink="/audits">Audits</a>). Il est
            ignoré si l’audit précédent de la même planification n’est pas terminé. Intervalle minimal : 15 minutes.</p>
        </section>
        @if (isAdmin()) {
          <section class="card form" data-testid="schedule-form">
            <h2>{{ scheduleForm().id ? 'Modifier la planification' : 'Nouvelle planification' }}</h2>
            <div class="fields">
              <label>Nom <input type="text" maxlength="120" [value]="scheduleForm().name" (input)="patchSchedule({ name: $any($event.target).value })" /></label>
              <label>Expression cron
                <input type="text" class="mono" [value]="scheduleForm().cronExpression" (input)="patchSchedule({ cronExpression: $any($event.target).value })" placeholder="0 2 * * *" />
                <span class="small muted">{{ cronLabel(scheduleForm().cronExpression) }}</span>
              </label>
              <label>Modèles
                <select (change)="patchSchedule({ cronExpression: $any($event.target).value })">
                  <option value="">—</option>
                  @for (p of presets; track p.cron) { <option [value]="p.cron">{{ p.label }}</option> }
                </select>
              </label>
              <label>Fuseau horaire <input type="text" [value]="scheduleForm().timeZone" (input)="patchSchedule({ timeZone: $any($event.target).value })" /></label>
            </div>
            <fieldset>
              <legend>Périmètre</legend>
              <label class="inline"><input type="radio" name="scope" [checked]="scheduleForm().scope === 'ALL_SELECTED'" (change)="patchSchedule({ scope: 'ALL_SELECTED' })" />
                tous les dépôts sélectionnés pour l’audit (y compris ceux ajoutés plus tard)</label>
              <label class="inline"><input type="radio" name="scope" [checked]="scheduleForm().scope === 'REPOSITORIES'" (change)="selectRepositoriesScope()" />
                certains dépôts</label>
              @if (scheduleForm().scope === 'REPOSITORIES') {
                <div class="repo-list">
                  @for (r of targets(); track r.id) {
                    <label class="inline small"><input type="checkbox" [checked]="scheduleForm().repositoryIds.includes(r.id)" (change)="toggleRepository(r.id)" /> {{ r.fullName }}</label>
                  } @empty { <p class="empty small">Aucun dépôt sélectionné pour l’audit.</p> }
                </div>
              }
            </fieldset>
            <label class="inline"><input type="checkbox" [checked]="scheduleForm().enabled" (change)="patchSchedule({ enabled: $any($event.target).checked })" /> active</label>
            <div class="actions">
              <button type="button" class="primary" (click)="saveSchedule()" [disabled]="busy()">Enregistrer</button>
              @if (scheduleForm().id) { <button type="button" (click)="resetScheduleForm()">Annuler</button> }
            </div>
          </section>
        }
      }

      @case ('webhooks') {
        @if (!isAdmin()) {
          <p class="empty">Réservé aux administrateurs.</p>
        } @else {
          <section class="card">
            <h2>Alertes (webhooks)</h2>
            @if (webhooks().length === 0) {
              <p class="empty">Aucune alerte configurée.</p>
            } @else {
              <div class="table-wrap"><table class="data">
                <thead><tr><th>Nom</th><th>Destination</th><th>Déclencheurs</th><th>Dernier envoi</th><th></th></tr></thead>
                <tbody>
                  @for (w of webhooks(); track w.id) {
                    <tr data-testid="webhook">
                      <td><strong>{{ w.name }}</strong> @if (!w.enabled) { <span class="pill">désactivée</span> }
                        <div class="small muted">{{ w.format === 'SLACK' ? 'Slack / Mattermost / Rocket.Chat' : 'JSON générique' }}{{ w.hasSecret ? ' · signée' : '' }}</div></td>
                      <td class="mono">{{ w.url }}</td>
                      <td class="small">{{ eventsLabel(w) }}</td>
                      <td class="small">@if (w.lastStatus) { <span class="pill" [attr.data-status]="w.lastStatus === 'DELIVERED' ? 'SUCCEEDED' : w.lastStatus">{{ deliveryLabel(w.lastStatus) }}</span> } @else { — }</td>
                      <td class="actions">
                        <button type="button" (click)="testWebhook(w)" [disabled]="busy()">Tester</button>
                        <button type="button" (click)="showDeliveries(w)">Envois</button>
                        <button type="button" (click)="editWebhook(w)">Modifier</button>
                        <button type="button" class="danger" (click)="deleteWebhook(w)">Supprimer</button>
                      </td>
                    </tr>
                    @if (testResult()?.id === w.id) {
                      <tr><td colspan="5" [class.error]="!testResult()!.result.delivered" class="small" data-testid="test-result">{{ testResult()!.result.message }}</td></tr>
                    }
                    @if (deliveriesOf() === w.id) {
                      <tr><td colspan="5">
                        @for (d of deliveries(); track d.id) {
                          <div class="small">{{ d.createdAt | date: 'dd/MM HH:mm' }} · {{ d.event }} · {{ deliveryLabel(d.status) }} ({{ d.attempts }} essai(s))
                            @if (d.httpStatus) { · HTTP {{ d.httpStatus }} } @if (d.error) { · {{ d.error }} }</div>
                        } @empty { <span class="small muted">Aucun envoi.</span> }
                      </td></tr>
                    }
                  }
                </tbody>
              </table></div>
            }
            <p class="small muted">Envoi par le worker, 6 essais au plus (1 min, 5 min, 30 min, 2 h, 6 h). Le message contient titres et
              emplacements, jamais de code ni de preuve. Signature : en-tête <span class="mono">X-Saytu-Signature: sha256=HMAC(secret, horodatage + "." + corps)</span>.</p>
          </section>
          <section class="card form" data-testid="webhook-form">
            <h2>{{ webhookForm().id ? 'Modifier l’alerte' : 'Nouvelle alerte' }}</h2>
            <div class="fields">
              <label>Nom <input type="text" maxlength="120" [value]="webhookForm().name" (input)="patchWebhook({ name: $any($event.target).value })" /></label>
              <label>URL <input type="url" [value]="webhookForm().url" (input)="patchWebhook({ url: $any($event.target).value })"
                     [placeholder]="webhookForm().id ? 'inchangée (laisser vide)' : 'https://…'" /></label>
              <label>Format
                <select [value]="webhookForm().format" (change)="patchWebhook({ format: $any($event.target).value })">
                  <option value="GENERIC">JSON générique</option>
                  <option value="SLACK">Slack / Mattermost / Rocket.Chat</option>
                </select>
              </label>
              <label>Gravité minimale
                <select [value]="webhookForm().minSeverity" (change)="patchWebhook({ minSeverity: $any($event.target).value })">
                  <option value="CRITICAL">Critique</option><option value="HIGH">Élevée</option><option value="MEDIUM">Moyenne</option>
                </select>
              </label>
            </div>
            <label class="inline"><input type="checkbox" [checked]="webhookForm().events.includes('NEW_FINDINGS')" (change)="toggleEvent('NEW_FINDINGS')" /> nouvelles vulnérabilités</label>
            <label class="inline"><input type="checkbox" [checked]="webhookForm().events.includes('SCAN_COMPLETED')" (change)="toggleEvent('SCAN_COMPLETED')" /> fin de chaque audit de branche</label>
            <label class="inline"><input type="checkbox" [checked]="webhookForm().enabled" (change)="patchWebhook({ enabled: $any($event.target).checked })" /> active</label>
            @if (webhookForm().id) {
              <label class="inline"><input type="checkbox" [checked]="webhookForm().changeSecret" (change)="patchWebhook({ changeSecret: $any($event.target).checked })" /> changer le secret de signature</label>
            }
            @if (!webhookForm().id || webhookForm().changeSecret) {
              <div class="fields">
                <label>Secret de signature (facultatif) <input type="text" class="mono" [value]="webhookForm().secret" (input)="patchWebhook({ secret: $any($event.target).value })" /></label>
                <button type="button" class="align-end" (click)="patchWebhook({ secret: generate() })">Générer</button>
              </div>
            }
            <div class="actions">
              <button type="button" class="primary" (click)="saveWebhook()" [disabled]="busy()">Enregistrer</button>
              @if (webhookForm().id) { <button type="button" (click)="resetWebhookForm()">Annuler</button> }
            </div>
          </section>
        }
      }

      @case ('users') {
        @if (!isAdmin()) {
          <p class="empty">Réservé aux administrateurs.</p>
        } @else {
          <section class="card">
            <h2>Utilisateurs</h2>
            @if (userStatus(); as st) {
              @if (!st.configured) {
                <p class="notice" data-testid="users-not-configured">{{ st.message }}</p>
              } @else {
                <div class="table-wrap"><table class="data">
                  <thead><tr><th>Utilisateur</th><th>Rôle</th><th>État</th><th></th></tr></thead>
                  <tbody>
                    @for (u of users(); track u.id) {
                      <tr data-testid="user">
                        <td><strong>{{ u.username }}</strong> @if (u.self) { <span class="pill">vous</span> }
                          <div class="small muted">{{ fullName(u) }} {{ u.email }}</div>
                          @if (u.requiredActions.length) { <div class="small muted">à faire à la connexion : {{ u.requiredActions.join(', ') }}</div> }</td>
                        <td>
                          <select [value]="u.role ?? ''" (change)="changeRole(u, $any($event.target).value)" [disabled]="busy()">
                            @if (!u.role) { <option value="">aucun</option> }
                            @for (r of roles; track r) { <option [value]="r">{{ roleLabel(r) }}</option> }
                          </select>
                        </td>
                        <td>{{ u.enabled ? 'actif' : 'désactivé' }}</td>
                        <td class="actions">
                          <button type="button" (click)="setEnabled(u, !u.enabled)" [disabled]="busy() || u.self">{{ u.enabled ? 'Désactiver' : 'Réactiver' }}</button>
                          <button type="button" (click)="resetPassword(u)" [disabled]="busy()">Nouveau mot de passe</button>
                        </td>
                      </tr>
                    }
                  </tbody>
                </table></div>
              }
            }
          </section>
          @if (credentials(); as c) {
            <section class="card notice" data-testid="credentials">
              <h2>Mot de passe temporaire de {{ c.user.username }}</h2>
              <p class="mono big">{{ c.temporaryPassword }}</p>
              <p class="small">Affiché une seule fois : transmettez-le par un canal sûr. Il devra être changé à la première connexion.</p>
              <button type="button" (click)="credentials.set(null)">J’ai noté le mot de passe</button>
            </section>
          }
          @if (userStatus()?.configured) {
            <section class="card form">
              <h2>Nouvel utilisateur</h2>
              <div class="fields">
                <label>Identifiant <input #nu type="text" maxlength="60" /></label>
                <label>E-mail <input #ne type="email" /></label>
                <label>Prénom <input #nf type="text" /></label>
                <label>Nom <input #nl type="text" /></label>
                <label>Rôle
                  <select #nr>@for (r of roles; track r) { <option [value]="r" [selected]="r === 'VIEWER'">{{ roleLabel(r) }}</option> }</select>
                </label>
              </div>
              <button type="button" class="primary" (click)="createUser(nu.value, ne.value, nf.value, nl.value, nr.value)" [disabled]="busy()">Créer</button>
            </section>
          }
        }
      }

      @case ('ai') {
        @if (ai(); as a) {
          <section class="card form" data-testid="ai-form">
            <h2>IA locale (Ollama, optionnelle)</h2>
            <p class="small muted">Ajoute une explication libre à la correction proposée d’une vulnérabilité. Le modèle tourne sur votre
              serveur : aucune donnée ne sort. Le code du dépôt n’est pas envoyé (il n’est pas conservé après l’audit), seulement le
              titre, la règle, l’emplacement et l’extrait masqué. Rien n’est jamais appliqué automatiquement.</p>
            <label class="inline"><input type="checkbox" [checked]="a.enabled" [disabled]="!isAdmin()" (change)="patchAi({ enabled: $any($event.target).checked })" /> activée</label>
            <div class="fields">
              <label>URL d’Ollama <input type="text" [value]="a.baseUrl" [disabled]="!isAdmin()" (input)="patchAi({ baseUrl: $any($event.target).value })" /></label>
              <label>Modèle <input type="text" [value]="a.model" [disabled]="!isAdmin()" (input)="patchAi({ model: $any($event.target).value })" /></label>
              <label>Délai (s) <input type="number" min="10" max="600" [value]="a.timeoutSeconds" [disabled]="!isAdmin()" (input)="patchAi({ timeoutSeconds: $any($event.target).valueAsNumber })" /></label>
            </div>
            @if (isAdmin()) {
              <div class="actions">
                <button type="button" class="primary" (click)="saveAi()" [disabled]="busy()">Enregistrer</button>
                <button type="button" (click)="testAi()" [disabled]="busy()">Tester la connexion</button>
              </div>
            }
            @if (aiTest(); as t) {
              <p class="small" [class.error]="!t.modelAvailable" data-testid="ai-test">{{ t.message }}
                @if (t.models.length) { <span class="muted">(modèles installés : {{ t.models.join(', ') }})</span> }</p>
            }
            <h3>Installation</h3>
            <pre>docker compose --profile ai up -d
docker compose exec ollama ollama pull {{ a.model }}</pre>
            <p class="small muted">Le modèle par défaut (qwen2.5-coder 7B, licence Apache-2.0) demande environ 8 Go de mémoire. Vérifiez la
              licence de tout autre modèle avant de l’utiliser.</p>
          </section>
        }
      }
    }
  `,
  styleUrl: '../../shared/page.css',
  styles: `
    .tabs { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
    .tabs button[aria-selected="true"] { background: var(--saytu-accent-soft); border-color: var(--saytu-accent); color: var(--saytu-accent); font-weight: 600; }
    section.card { margin-bottom: 14px; }
    .form { display: flex; flex-direction: column; gap: 10px; }
    .fields { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
    label { display: flex; flex-direction: column; gap: 4px; font-size: .88rem; }
    label.inline { flex-direction: row; align-items: center; gap: 8px; }
    input, select { font: inherit; font-size: .88rem; padding: .4rem .5rem; border-radius: 6px; border: 1px solid var(--saytu-border);
                    background: var(--saytu-surface); color: var(--saytu-text); min-width: 0; }
    fieldset { border: 1px solid var(--saytu-border); border-radius: 8px; padding: 8px 12px; display: flex; flex-direction: column; gap: 6px; }
    .repo-list { max-height: 220px; overflow-y: auto; padding-left: 22px; display: flex; flex-direction: column; gap: 3px; }
    .actions { display: flex; flex-wrap: wrap; gap: 6px; }
    td.actions { white-space: nowrap; }
    .align-end { align-self: end; }
    .notice { border-left: 3px solid var(--saytu-medium); padding-left: 10px; }
    .big { font-size: 1.2rem; }
  `,
})
export class SettingsPage implements OnInit {
  private readonly api = inject(SettingsApi);
  private readonly sources = inject(SourcesApi);
  private readonly auth = inject(AuthService);

  readonly tabs: { id: Tab; label: string }[] = [
    { id: 'schedules', label: 'Planification' }, { id: 'webhooks', label: 'Alertes' },
    { id: 'users', label: 'Utilisateurs' }, { id: 'ai', label: 'IA locale' },
  ];
  readonly presets = CRON_PRESETS;
  readonly roles = ['VIEWER', 'AUDITOR', 'ADMIN'];
  readonly isAdmin = computed(() => this.auth.hasRole('ADMIN'));
  readonly tab = signal<Tab>('schedules');
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  readonly schedules = signal<Schedule[]>([]);
  readonly targets = signal<Repository[]>([]);
  readonly scheduleForm = signal<ScheduleForm>(this.emptySchedule());

  readonly webhooks = signal<Webhook[]>([]);
  readonly webhookForm = signal<WebhookForm>(this.emptyWebhook());
  readonly testResult = signal<{ id: string; result: TestResult } | null>(null);
  readonly deliveriesOf = signal<string | null>(null);
  readonly deliveries = signal<Delivery[]>([]);

  readonly userStatus = signal<UserStatus | null>(null);
  readonly users = signal<AppUser[]>([]);
  readonly credentials = signal<Credentials | null>(null);

  readonly ai = signal<AiSettings | null>(null);
  readonly aiTest = signal<AiTest | null>(null);

  ngOnInit(): void {
    this.open('schedules');
  }

  open(tab: Tab): void {
    this.tab.set(tab);
    this.error.set(null);
    switch (tab) {
      case 'schedules':
        this.api.schedules().subscribe({ next: s => this.schedules.set(s), error: e => this.fail(e, 'Planifications indisponibles.') });
        break;
      case 'webhooks':
        if (this.isAdmin()) {
          this.loadWebhooks();
        }
        break;
      case 'users':
        if (this.isAdmin()) {
          this.api.userStatus().subscribe({
            next: st => {
              this.userStatus.set(st);
              if (st.configured) {
                this.loadUsers();
              }
            },
            error: e => this.fail(e, 'Statut indisponible.'),
          });
        }
        break;
      case 'ai':
        this.api.ai().subscribe({ next: a => this.ai.set(a), error: e => this.fail(e, 'Paramètres indisponibles.') });
        break;
    }
  }

  // ---------------------------------------------------------------- schedules

  cronLabel(c: string): string {
    return describeCron(c);
  }

  private emptySchedule(): ScheduleForm {
    let zone = 'UTC';
    try {
      zone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch {
      /* keep UTC */
    }
    return { id: null, name: '', cronExpression: '0 2 * * *', timeZone: zone, scope: 'ALL_SELECTED', enabled: true, repositoryIds: [] };
  }

  patchSchedule(p: Partial<ScheduleForm>): void {
    this.scheduleForm.update(f => ({ ...f, ...p }));
  }

  resetScheduleForm(): void {
    this.scheduleForm.set(this.emptySchedule());
  }

  selectRepositoriesScope(): void {
    this.patchSchedule({ scope: 'REPOSITORIES' });
    if (this.targets().length === 0) {
      this.sources.scanTargets('', 0, 200).subscribe({ next: p => this.targets.set(p.items), error: e => this.fail(e, 'Dépôts indisponibles.') });
    }
  }

  toggleRepository(id: string): void {
    const ids = this.scheduleForm().repositoryIds;
    this.patchSchedule({ repositoryIds: ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id] });
  }

  editSchedule(s: Schedule): void {
    this.scheduleForm.set({ id: s.id, name: s.name, cronExpression: s.cronExpression, timeZone: s.timeZone,
      scope: s.scope === 'NAMESPACES' ? 'ALL_SELECTED' : s.scope, enabled: s.enabled, repositoryIds: s.repositoryIds });
    if (s.scope === 'REPOSITORIES') {
      this.selectRepositoriesScope();
    }
  }

  saveSchedule(): void {
    const f = this.scheduleForm();
    this.run(this.api.saveSchedule(f.id, { name: f.name, cronExpression: f.cronExpression, timeZone: f.timeZone, scope: f.scope,
      enabled: f.enabled, repositoryIds: f.scope === 'REPOSITORIES' ? f.repositoryIds : [], namespaceIds: [] }), () => {
      this.resetScheduleForm();
      this.open('schedules');
    });
  }

  deleteSchedule(s: Schedule): void {
    this.run(this.api.deleteSchedule(s.id), () => this.open('schedules'));
  }

  // ---------------------------------------------------------------- webhooks

  private emptyWebhook(): WebhookForm {
    return { id: null, name: '', url: '', format: 'GENERIC', minSeverity: 'CRITICAL', events: ['NEW_FINDINGS'], enabled: true,
      secret: '', changeSecret: false };
  }

  private loadWebhooks(): void {
    this.api.webhooks().subscribe({ next: w => this.webhooks.set(w), error: e => this.fail(e, 'Alertes indisponibles.') });
  }

  patchWebhook(p: Partial<WebhookForm>): void {
    this.webhookForm.update(f => ({ ...f, ...p }));
  }

  resetWebhookForm(): void {
    this.webhookForm.set(this.emptyWebhook());
  }

  toggleEvent(e: string): void {
    const ev = this.webhookForm().events;
    this.patchWebhook({ events: ev.includes(e) ? ev.filter(x => x !== e) : [...ev, e] });
  }

  generate(): string {
    return randomSecret();
  }

  editWebhook(w: Webhook): void {
    this.webhookForm.set({ id: w.id, name: w.name, url: '', format: w.format, minSeverity: w.minSeverity, events: w.events,
      enabled: w.enabled, secret: '', changeSecret: false });
  }

  saveWebhook(): void {
    const f = this.webhookForm();
    const secret = f.id && !f.changeSecret ? null : f.secret;
    this.run(this.api.saveWebhook(f.id, { name: f.name, url: f.url, format: f.format, minSeverity: f.minSeverity, events: f.events,
      enabled: f.enabled, secret }), () => {
      this.resetWebhookForm();
      this.loadWebhooks();
    });
  }

  deleteWebhook(w: Webhook): void {
    this.run(this.api.deleteWebhook(w.id), () => this.loadWebhooks());
  }

  testWebhook(w: Webhook): void {
    this.run(this.api.testWebhook(w.id), r => this.testResult.set({ id: w.id, result: r }));
  }

  showDeliveries(w: Webhook): void {
    if (this.deliveriesOf() === w.id) {
      this.deliveriesOf.set(null);
      return;
    }
    this.api.deliveries(w.id).subscribe({ next: d => {
      this.deliveries.set(d);
      this.deliveriesOf.set(w.id);
    }, error: e => this.fail(e, 'Envois indisponibles.') });
  }

  eventsLabel(w: Webhook): string {
    const labels: string[] = [];
    if (w.events.includes('NEW_FINDINGS')) {
      labels.push(`nouvelles vulnérabilités ≥ ${({ CRITICAL: 'critique', HIGH: 'élevée', MEDIUM: 'moyenne' } as Record<string, string>)[w.minSeverity] ?? w.minSeverity}`);
    }
    if (w.events.includes('SCAN_COMPLETED')) {
      labels.push('fin d’audit');
    }
    return labels.join(' · ');
  }

  deliveryLabel(s: string): string {
    return DELIVERY_LABELS[s] ?? s;
  }

  // ---------------------------------------------------------------- users

  private loadUsers(): void {
    this.api.users().subscribe({ next: u => this.users.set(u), error: e => this.fail(e, 'Utilisateurs indisponibles.') });
  }

  roleLabel(r: string): string {
    return ROLE_LABELS[r] ?? r;
  }

  fullName(u: AppUser): string {
    return [u.firstName, u.lastName].filter(Boolean).join(' ');
  }

  changeRole(u: AppUser, role: string): void {
    this.run(this.api.changeRole(u.id, role), () => this.loadUsers(), () => this.loadUsers());
  }

  setEnabled(u: AppUser, enabled: boolean): void {
    this.run(this.api.setEnabled(u.id, enabled), () => this.loadUsers());
  }

  resetPassword(u: AppUser): void {
    this.run(this.api.resetPassword(u.id), c => this.credentials.set(c));
  }

  createUser(username: string, email: string, firstName: string, lastName: string, role: string): void {
    this.run(this.api.createUser({ username, email, firstName, lastName, role }), c => {
      this.credentials.set(c);
      this.loadUsers();
    });
  }

  // ---------------------------------------------------------------- AI

  patchAi(p: Partial<AiSettings>): void {
    this.ai.update(a => (a ? { ...a, ...p } : a));
  }

  saveAi(): void {
    const a = this.ai();
    if (a) {
      this.run(this.api.saveAi(a), s => this.ai.set(s));
    }
  }

  testAi(): void {
    this.run(this.api.testAi(), t => this.aiTest.set(t));
  }

  // ---------------------------------------------------------------- helpers

  private run<T>(call: Observable<T>, done: (v: T) => void, failed?: () => void): void {
    this.busy.set(true);
    this.error.set(null);
    call.subscribe({
      next: v => {
        this.busy.set(false);
        done(v);
      },
      error: e => {
        this.busy.set(false);
        this.fail(e, 'L’opération a échoué.');
        failed?.();
      },
    });
  }

  private fail(e: unknown, fallback: string): void {
    this.error.set(problem(e, fallback));
  }
}
