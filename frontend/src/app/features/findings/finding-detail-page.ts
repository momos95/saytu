import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { SEVERITY_LABELS, SHORT_SCANNER_LABELS, location, shortSha } from '../audits/audits.logic';
import { InsightsApi } from './insights.api';
import { STATUS_LABELS, TYPE_LABELS } from './insights.logic';
import { AiExplanation, FindingDetail } from './insights.model';

/** One finding: evidence (secrets masked), references, recommendation, occurrences, triage. */
@Component({
  selector: 'saytu-finding-detail-page',
  imports: [DatePipe, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p class="small"><a routerLink="/findings">← Vulnérabilités</a></p>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
    @if (detail(); as d) {
      <header class="page-header">
        <div>
          <span class="sev" [attr.data-severity]="d.finding.severity">{{ severityLabel(d.finding.severity) }}</span>
          <h1>{{ d.finding.title }}</h1>
        </div>
        <span class="pill big" [attr.data-status]="d.finding.status" data-testid="status">{{ statusLabel(d.finding.status) }}</span>
      </header>

      <div class="grid">
        <section class="card">
          <h2>Contexte</h2>
          <dl class="meta">
            <dt>Dépôt</dt><dd><a [routerLink]="['/repositories', d.finding.repositoryId]">{{ d.finding.repositoryName }}</a> · {{ d.finding.branch }}</dd>
            <dt>Commit</dt><dd class="mono">{{ sha(d.finding.commitSha) }}</dd>
            <dt>Emplacement</dt><dd class="mono">{{ where() || '—' }}</dd>
            <dt>Type</dt><dd>{{ typeLabel(d.finding.type) }}</dd>
            <dt>Règle</dt><dd class="mono">{{ scannerLabel(d.finding.scanner) }} · {{ d.finding.ruleId }}</dd>
            @if (d.finding.scanners.length > 1) {
              <dt>Détectée aussi par</dt><dd>{{ others(d) }}</dd>
            }
            @if (d.finding.cwes.length) {
              <dt>CWE</dt>
              <dd>@for (c of d.finding.cwes; track c) {
                <a [href]="cweUrl(c)" target="_blank" rel="noopener noreferrer">{{ c }}</a>@if (!$last) {, }
              }</dd>
            }
            @if (d.finding.cve) { <dt>CVE</dt><dd>{{ d.finding.cve }}</dd> }
            @if (d.finding.cvssScore !== null) { <dt>CVSS</dt><dd>{{ d.finding.cvssScore }} @if (d.cvssVector) { <span class="mono muted">{{ d.cvssVector }}</span> }</dd> }
            @if (d.finding.packageName) {
              <dt>Paquet</dt>
              <dd>{{ d.finding.packageName }} {{ d.finding.packageVersion }} @if (d.packageEcosystem) { <span class="muted">({{ d.packageEcosystem }})</span> }
                @if (d.finding.fixedVersion) { → corrigé en <strong>{{ d.finding.fixedVersion }}</strong> }</dd>
            }
            <dt>Vue depuis</dt><dd>{{ d.finding.firstSeenAt | date: 'dd/MM/yyyy HH:mm' }} (dernière détection {{ d.finding.lastSeenAt | date: 'dd/MM/yyyy HH:mm' }})</dd>
            @if (d.resolvedAt) { <dt>Corrigée le</dt><dd>{{ d.resolvedAt | date: 'dd/MM/yyyy HH:mm' }}</dd> }
          </dl>
        </section>

        <section class="card triage" aria-label="Triage">
          <h2>Statut</h2>
          @if (d.statusReason) {
            <p class="small">« {{ d.statusReason }} » — {{ d.statusChangedBy }}, {{ d.statusChangedAt | date: 'dd/MM/yyyy HH:mm' }}</p>
          }
          @if (d.finding.status === 'RESOLVED') {
            <p class="small muted">Corrigée : plus détectée par un audit où le scanner concerné a réussi. Elle sera rouverte
              automatiquement si un audit la retrouve.</p>
          } @else if (canTriage()) {
            @if (d.finding.status === 'OPEN') {
              <label class="small">Justification (obligatoire)
                <textarea #reason rows="3" maxlength="2000" placeholder="ex. code de test, contrôle compensatoire, valeur non sensible…"></textarea>
              </label>
              <div class="actions">
                <button type="button" (click)="change('ACCEPTED_RISK', reason.value)" [disabled]="busy()">Accepter le risque</button>
                <button type="button" (click)="change('FALSE_POSITIVE', reason.value)" [disabled]="busy()">Faux positif</button>
              </div>
            } @else {
              <button type="button" (click)="change('OPEN', '')" [disabled]="busy()">Rouvrir</button>
            }
            @if (triageError()) { <p class="error small" role="alert">{{ triageError() }}</p> }
            <p class="small muted">Un statut posé à la main n’est jamais modifié par un audit. Chaque changement est historisé.</p>
          } @else {
            <p class="small muted">Le triage est réservé aux rôles AUDITOR et ADMIN.</p>
          }
        </section>
      </div>

      <div class="stack">
        @if (d.description && d.description !== d.finding.title) {
          <section class="card"><h2>Description</h2><p class="text">{{ d.description }}</p></section>
        }
        @if (d.evidence) {
          <section class="card"><h2>Preuve <span class="muted small">(secrets masqués)</span></h2><pre data-testid="evidence">{{ d.evidence }}</pre></section>
        }
        @if (d.suggestion; as sg) {
          <section class="card suggestion" data-testid="suggestion">
            <h2>Correction proposée <span class="muted small">— {{ sg.topic }}</span></h2>
            @if (!sg.specific) {
              <p class="small muted">Recommandation générale de la catégorie : pas de guide détaillé pour cette règle.</p>
            }
            <p class="text">{{ sg.explanation }}</p>
            <p class="impact"><strong>Impact :</strong> {{ sg.impact }}</p>
            <h3>Étapes</h3>
            <ol class="steps">@for (st of sg.steps; track $index) { <li>{{ st }}</li> }</ol>
            @if (sg.vulnerableExample || sg.fixedCodeExample) {
              <div class="examples">
                @if (sg.vulnerableExample) {
                  <div><h3>À éviter <span class="muted small">({{ sg.exampleLanguage }})</span></h3><pre class="bad">{{ sg.vulnerableExample }}</pre></div>
                }
                @if (sg.fixedCodeExample) {
                  <div><h3>Exemple corrigé <span class="muted small">({{ sg.exampleLanguage }})</span></h3><pre class="good" data-testid="fixed-example">{{ sg.fixedCodeExample }}</pre></div>
                }
              </div>
            }
            @if (sg.suggestedTests.length) {
              <h3>Tests à ajouter</h3>
              <ul class="steps">@for (t of sg.suggestedTests; track $index) { <li>{{ t }}</li> }</ul>
            }
            <p class="small muted">Suggestion déterministe de SAYTU (aucune IA, aucun envoi externe), à adapter au contexte.
              Aucune correction n’est appliquée automatiquement.</p>
          </section>
        }

        @if (aiEnabled() || ai()) {
          <section class="card ai" data-testid="ai">
            <h2>Explication par IA locale</h2>
            @if (ai(); as x) {
              <p class="text">{{ x.content.explanation }}</p>
              @if (x.content.impact) { <p><strong>Impact :</strong> {{ x.content.impact }}</p> }
              @if (x.content.steps.length) {
                <h3>Correction</h3>
                <ol class="steps">@for (st of x.content.steps; track $index) { <li>{{ st }}</li> }</ol>
              }
              @if (x.content.fixedCodeExample) { <h3>Exemple</h3><pre>{{ x.content.fixedCodeExample }}</pre> }
              @if (x.content.suggestedTests.length) {
                <h3>Tests</h3>
                <ul class="steps">@for (t of x.content.suggestedTests; track $index) { <li>{{ t }}</li> }</ul>
              }
              <p class="small muted">Généré par {{ x.providerId }} le {{ x.createdAt | date: 'dd/MM/yyyy HH:mm' }}. Texte produit par un
                modèle : à vérifier ; rien n’est appliqué automatiquement.</p>
            } @else {
              <p class="small muted">Le modèle local reçoit le titre, la règle, l’emplacement et l’extrait masqué (pas le code du dépôt).</p>
            }
            @if (aiEnabled() && canTriage()) {
              <button type="button" (click)="explain()" [disabled]="aiBusy()">{{ aiBusy() ? 'Génération… (jusqu’à 2 min)' : (ai() ? 'Régénérer' : 'Expliquer avec l’IA locale') }}</button>
            }
            @if (aiError()) { <p class="error small" role="alert">{{ aiError() }}</p> }
          </section>
        }

        <section class="card">
          <h2>Indication du scanner</h2>
          @if (d.recommendation) {
            <p class="text" data-testid="recommendation">{{ d.recommendation }}</p>
          } @else {
            <p class="empty">Le scanner ne fournit pas de recommandation pour cette règle.</p>
          }
          @if (references(d).length) {
            <h3>Références</h3>
            <ul class="refs">
              @for (r of references(d); track r) {
                <li>@if (isLink(r)) { <a [href]="r" target="_blank" rel="noopener noreferrer">{{ r }}</a> } @else { {{ r }} }</li>
              }
            </ul>
          }
        </section>

        @if (d.history.length) {
          <section class="card">
            <h2>Historique du statut</h2>
            <div class="table-wrap"><table class="data">
              <thead><tr><th>Date</th><th>Changement</th><th>Par</th><th>Justification</th></tr></thead>
              <tbody>
                @for (h of d.history; track $index) {
                  <tr><td class="small">{{ h.changedAt | date: 'dd/MM/yyyy HH:mm' }}</td>
                    <td>{{ statusLabel(h.fromStatus ?? '') }} → {{ statusLabel(h.toStatus) }}</td>
                    <td>{{ h.changedBy }}</td><td>{{ h.reason }}</td></tr>
                }
              </tbody>
            </table></div>
          </section>
        }

        <section class="card">
          <h2>Détections</h2>
          <div class="table-wrap"><table class="data">
            <thead><tr><th>Date</th><th>Scanner</th><th>Règle</th><th>Sévérité outil</th><th>Emplacement</th></tr></thead>
            <tbody>
              @for (o of d.occurrences; track $index) {
                <tr><td class="small">{{ o.detectedAt | date: 'dd/MM/yyyy HH:mm' }}</td><td>{{ scannerLabel(o.scanner) }}</td>
                  <td class="mono">{{ o.ruleId }}</td><td>{{ o.severity }}</td>
                  <td class="mono">{{ o.filePath }}{{ o.startLine ? ":" + o.startLine : "" }}</td></tr>
              }
            </tbody>
          </table></div>
        </section>
      </div>
    } @else if (!error()) {
      <p class="muted">Chargement…</p>
    }
  `,
  styleUrl: '../../shared/page.css',
  styles: `
    .page-header { align-items: flex-start; }
    .pill.big { font-size: .85rem; padding: .25rem .8rem; }
    .triage { display: flex; flex-direction: column; gap: 10px; }
    .triage label { display: flex; flex-direction: column; gap: 4px; }
    textarea { font: inherit; font-size: .88rem; padding: .45rem; border-radius: 6px; border: 1px solid var(--saytu-border);
               background: var(--saytu-surface); color: var(--saytu-text); resize: vertical; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .text { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }
    .refs { margin: 0; padding-left: 18px; font-size: .85rem; overflow-wrap: anywhere; }
    .suggestion { border-left: 3px solid var(--saytu-accent); }
    .ai { border-left: 3px solid var(--saytu-low); }
    .impact { margin: 8px 0; }
    .steps { margin: 0 0 10px; padding-left: 20px; display: flex; flex-direction: column; gap: 4px; }
    .examples { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); margin-bottom: 10px; }
    .examples h3 { margin-top: 4px; }
    pre.bad { border-left: 3px solid var(--saytu-critical); }
    pre.good { border-left: 3px solid var(--saytu-accent); }
  `,
})
export class FindingDetailPage implements OnInit {
  private readonly api = inject(InsightsApi);
  private readonly auth = inject(AuthService);

  /** route parameter (withComponentInputBinding) */
  readonly id = input.required<string>();
  readonly detail = signal<FindingDetail | null>(null);
  readonly error = signal<string | null>(null);
  readonly triageError = signal<string | null>(null);
  readonly busy = signal(false);
  readonly ai = signal<AiExplanation | null>(null);
  readonly aiEnabled = signal(false);
  readonly aiBusy = signal(false);
  readonly aiError = signal<string | null>(null);
  readonly canTriage = computed(() => this.auth.hasRole('AUDITOR') || this.auth.hasRole('ADMIN'));
  readonly where = computed(() => {
    const d = this.detail();
    return d ? location(d.finding) : '';
  });

  ngOnInit(): void {
    this.api.finding(this.id()).subscribe({
      next: d => this.detail.set(d),
      error: () => this.error.set('Vulnérabilité introuvable.'),
    });
    // optional: errors only hide the AI block
    this.api.aiEnabled().subscribe({ next: s => this.aiEnabled.set(s.enabled), error: () => this.aiEnabled.set(false) });
    this.api.aiExplanation(this.id()).subscribe({ next: x => this.ai.set(x), error: () => this.ai.set(null) });
  }

  explain(): void {
    this.aiBusy.set(true);
    this.aiError.set(null);
    this.api.generateAiExplanation(this.id()).subscribe({
      next: x => {
        this.aiBusy.set(false);
        this.ai.set(x);
      },
      error: (e: { error?: { detail?: string } }) => {
        this.aiBusy.set(false);
        this.aiError.set(e?.error?.detail ?? 'Le modèle local n’a pas répondu.');
      },
    });
  }

  change(status: string, reason: string): void {
    const text = reason.trim();
    if (status !== 'OPEN' && !text) {
      this.triageError.set('Indiquez une justification : elle sera conservée dans l’historique.');
      return;
    }
    this.busy.set(true);
    this.triageError.set(null);
    this.api.changeStatus(this.id(), status, text || null).subscribe({
      next: d => {
        this.busy.set(false);
        this.detail.set(d);
      },
      error: (e: { error?: { detail?: string } }) => {
        this.busy.set(false);
        this.triageError.set(e?.error?.detail ?? 'Le statut n’a pas pu être modifié.');
      },
    });
  }

  severityLabel(s: string): string {
    return SEVERITY_LABELS[s] ?? s;
  }

  statusLabel(s: string): string {
    return STATUS_LABELS[s] ?? s;
  }

  typeLabel(t: string): string {
    return TYPE_LABELS[t] ?? t;
  }

  scannerLabel(s: string): string {
    return SHORT_SCANNER_LABELS[s] ?? s;
  }

  others(d: FindingDetail): string {
    return d.finding.scanners.filter(s => s !== d.finding.scanner).map(s => this.scannerLabel(s)).join(', ');
  }

  sha(s: string | null): string {
    return s ? shortSha(s) : '—';
  }

  /** scanner references plus the suggestion's (cheat sheets, CWE, advisories), without duplicates */
  references(d: FindingDetail): string[] {
    return [...new Set([...d.references, ...(d.suggestion?.references ?? [])])];
  }

  isLink(r: string): boolean {
    return /^https?:\/\//.test(r);
  }

  /** "CWE-89" → MITRE page; anything else is not linked. */
  cweUrl(cwe: string): string | null {
    const m = /^CWE-(\d+)$/.exec(cwe);
    return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
  }
}
