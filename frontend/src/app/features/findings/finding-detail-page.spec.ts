import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { AppRole } from '../../core/auth/oidc';
import { fakeTokens } from '../../testing/fake-session';
import { FindingDetailPage } from './finding-detail-page';

const DETAIL = {
  finding: { id: 'f1', repositoryId: 'r1', repositoryName: 'acme/api', branch: 'main', type: 'SECRET', severity: 'HIGH',
    scanner: 'gitleaks', ruleId: 'generic-api-key', title: 'Generic API key', filePath: 'src/app.yml', startLine: 3, endLine: 3,
    cwes: ['CWE-798'], cve: null, cvssScore: null, packageName: null, packageVersion: null, fixedVersion: null, status: 'OPEN',
    firstSeenAt: '2026-11-05T10:00:00Z', lastSeenAt: '2026-11-06T10:00:00Z', commitSha: 'a'.repeat(40), scanners: ['gitleaks'] },
  description: 'A key', evidence: 'api_key: "****"', recommendation: 'Révoquer la clé puis la retirer du dépôt.',
  references: ['https://cwe.mitre.org/data/definitions/798.html'], cvssVector: null, packageEcosystem: null, resolvedAt: null,
  statusReason: null, statusChangedBy: null, statusChangedAt: null, occurrences: [], history: [],
  suggestion: { providerId: 'rule-based', topic: 'Secret dans le dépôt', explanation: 'Une valeur…', impact: 'Élevé : …',
    steps: ['Révoquer le secret', 'Le lire depuis l’environnement'], exampleLanguage: 'yaml', vulnerableExample: 'password: x',
    fixedCodeExample: 'password: ${DB_PASSWORD}', suggestedTests: ['Démarrer sans la variable'],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'], specific: true },
};

describe('FindingDetailPage', () => {
  let http: HttpTestingController;

  function render(roles: AppRole[]) {
    TestBed.configureTestingModule({
      imports: [FindingDetailPage],
      providers: [provideZonelessChangeDetection(), provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(roles));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(FindingDetailPage);
    fixture.componentRef.setInput('id', 'f1');
    fixture.detectChanges();
    http.expectOne('/api/v1/findings/f1').flush(DETAIL);
    return fixture;
  }

  afterEach(() => http.verify());

  it('shows the masked evidence and the recommendation; viewers cannot triage', async () => {
    const fixture = render(['VIEWER']);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="evidence"]')?.textContent).toBe('api_key: "****"');
    expect(el.querySelector('[data-testid="recommendation"]')?.textContent).toContain('Révoquer la clé');
    expect(el.querySelector('[data-testid="suggestion"]')?.textContent).toContain('Secret dans le dépôt');
    expect(el.querySelector('[data-testid="fixed-example"]')?.textContent).toBe('password: ${DB_PASSWORD}');
    expect(el.querySelectorAll('.refs a').length).toBe(2);
    expect(el.textContent).toContain('réservé aux rôles AUDITOR et ADMIN');
    expect(el.querySelector('textarea')).toBeNull();
  });

  it('requires a reason to declare a false positive', async () => {
    const fixture = render(['AUDITOR']);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const fp = Array.from(el.querySelectorAll('button')).find(b => b.textContent?.includes('Faux positif')) as HTMLButtonElement;
    fp.click();
    await fixture.whenStable();
    expect(el.textContent).toContain('Indiquez une justification');
    (el.querySelector('textarea') as HTMLTextAreaElement).value = 'clé de test';
    fp.click();
    const req = http.expectOne(r => r.method === 'PUT' && r.url === '/api/v1/findings/f1/status');
    expect(req.request.body).toEqual({ status: 'FALSE_POSITIVE', reason: 'clé de test' });
    req.flush({ ...DETAIL, finding: { ...DETAIL.finding, status: 'FALSE_POSITIVE' }, statusReason: 'clé de test',
      statusChangedBy: 'awa', statusChangedAt: '2026-11-06T11:00:00Z',
      history: [{ fromStatus: 'OPEN', toStatus: 'FALSE_POSITIVE', reason: 'clé de test', changedBy: 'awa', changedAt: '2026-11-06T11:00:00Z' }] });
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="status"]')?.textContent).toContain('Faux positif');
    expect(el.textContent).toContain('Rouvrir');
  });
});
