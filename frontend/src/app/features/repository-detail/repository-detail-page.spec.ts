import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { fakeTokens } from '../../testing/fake-session';
import { RepositoryDetailPage } from './repository-detail-page';

const zero = { SECURITY: 0, SECRET: 0, DEPENDENCY: 0, QUALITY: 0 };

describe('RepositoryDetailPage', () => {
  let http: HttpTestingController;

  it('shows each branch with its score and open findings, and audits on demand', async () => {
    TestBed.configureTestingModule({
      imports: [RepositoryDetailPage],
      providers: [provideZonelessChangeDetection(), provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(['AUDITOR']));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(RepositoryDetailPage);
    fixture.componentRef.setInput('id', 'r1');
    fixture.detectChanges();
    http.expectOne('/api/v1/repositories/r1/overview').flush({
      repository: { id: 'r1', fullName: 'acme/api', name: 'api', webUrl: 'https://gitlab.example.org/acme/api',
        defaultBranch: 'main', visibility: 'PRIVATE', archived: false, removed: false, languages: ['java', 'sql'],
        languagesUpdatedAt: null, lastActivityAt: null, namespaceId: 'n1', namespace: 'acme', connectionName: 'gl',
        providerType: 'GITLAB' },
      score: null,
      branches: [{ branch: 'main', score: null, openBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 }, openFindings: 2 }],
      openBySeverity: { CRITICAL: zero, HIGH: { ...zero, SECURITY: 2 }, MEDIUM: zero, LOW: zero, INFO: zero },
      trend: [], weeklyFlow: [], topRules: [], recentJobs: [],
      actionPlan: { branch: 'main', formulaVersion: 'v2', securityScore: 59, items: [{ kind: 'DEPENDENCY_UPGRADE',
        title: 'Mettre à jour log4j-core 2.14.1 vers 2.16.0 ou plus', target: 'log4j-core 2.14.1', fixedVersion: '2.16.0',
        severity: 'CRITICAL', findings: 2, securityBefore: 59, securityAfter: 90.9, gain: 31.9, exampleFindingId: 'f1',
        query: { repositoryId: 'r1', branch: 'main', status: 'OPEN', q: 'log4j-core' } }] },
      workflow: { status: 'FAIL', checkedAt: '2026-11-10T09:00:00Z', error: null, report: {
        status: 'FAIL', productionBranch: 'main', productionSha: 'a'.repeat(40), developSha: null, latestTag: 'v1.2.0',
        latestTagSha: 'c'.repeat(40), releaseTags: 3, checks: [
          { id: 'PRODUCTION_BRANCH', status: 'PASS', message: 'Branche de production : main.' },
          { id: 'DEVELOP_BRANCH', status: 'FAIL', message: 'Aucune branche develop.' },
          { id: 'PRODUCTION_ON_LATEST_TAG', status: 'FAIL', message: 'main (aaaaaaaa) ne pointe pas sur le dernier tag v1.2.0 (cccccccc).' },
        ] } },
    });
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('h1')?.textContent).toContain('acme/api');
    expect(el.textContent).toContain('GitLab');
    expect(el.querySelector('[data-testid="branch"]')?.textContent).toContain('pas encore de score');
    const wf = el.querySelector('[data-testid="workflow"]')!;
    expect(wf.querySelector('[data-testid="workflow-badge"]')?.textContent).toContain('non conforme');
    const checks = Array.from(wf.querySelectorAll('[data-testid="workflow-check"]'));
    expect(checks.map(c => c.getAttribute('data-status'))).toEqual(['FAIL', 'FAIL', 'PASS']);
    expect(checks[0].textContent).toContain('Branche de travail develop');
    expect(checks[1].textContent).toContain('ne pointe pas sur le dernier tag v1.2.0');
    expect(wf.textContent).toContain('3 tag(s) de version');
    const action = el.querySelector('[data-testid="action"]')!.textContent!;
    expect(action).toContain('Mettre à jour log4j-core');
    expect(action).toContain('+31,9 pts sécurité');
    expect(action).toContain('(59 → 91)');
    const audit = Array.from(el.querySelectorAll('button')).find(b => b.textContent?.includes('Auditer ce dépôt')) as HTMLButtonElement;
    audit.click();
    const req = http.expectOne(r => r.method === 'POST' && r.url === '/api/v1/scans');
    expect(req.request.body).toEqual({ allTargets: false, repositoryIds: ['r1'] });
    req.flush({ id: 'run9' });
    http.verify();
  });
});
