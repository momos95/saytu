import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { AppRole } from '../../core/auth/oidc';
import { fakeTokens } from '../../testing/fake-session';
import { AuditsPage } from './audits-page';

const RUN = { id: 'run1', triggerType: 'MANUAL', requestedBy: 'awa', status: 'PARTIAL', totalJobs: 1, finishedJobs: 1,
  problemJobs: 1, newFindings: 2, createdAt: '2026-11-05T10:00:00Z', startedAt: '2026-11-05T10:00:01Z',
  finishedAt: '2026-11-05T10:01:01Z', planned: true, cancelRequested: false, errorMessage: null, scope: 'ALL_TARGETS' };

describe('AuditsPage', () => {
  let http: HttpTestingController;

  function render(roles: AppRole[]) {
    TestBed.configureTestingModule({
      imports: [AuditsPage],
      providers: [provideZonelessChangeDetection(), provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(roles));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AuditsPage);
    fixture.detectChanges();
    http.expectOne(r => r.url === '/api/v1/scans').flush({ items: [RUN], page: 0, size: 20, totalElements: 1, totalPages: 1 });
    return fixture;
  }

  afterEach(() => http.verify());

  it('lists audits and hides the launch button from viewers', async () => {
    const fixture = render(['VIEWER']);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="run"]')?.textContent).toContain('Terminé partiellement');
    expect(el.querySelector('[data-testid="launch"]')).toBeNull();
  });

  it('shows why a scanner did not complete instead of "no finding"', async () => {
    const fixture = render(['AUDITOR']);
    await fixture.whenStable();
    (fixture.nativeElement.querySelector('.run-open') as HTMLButtonElement).click();
    http.expectOne('/api/v1/scans/run1').flush({ run: RUN, planningNotes: [], jobs: [{ id: 'j1', repositoryId: 'r1',
      repositoryName: 'acme/api', branch: 'main', commitSha: 'a'.repeat(40), status: 'PARTIAL', attempt: 1,
      queuedAt: RUN.createdAt, startedAt: RUN.startedAt, finishedAt: RUN.finishedAt, errorMessage: null,
      checkoutBytes: 2048, findingsCount: 2, newFindings: 2, resolvedFindings: 0, scanners: [
        { scanner: 'opengrep', status: 'SUCCEEDED', toolVersion: '1.33.1', rulesetVersion: 'saytu@x', durationMs: 2100, findingsCount: 2, errorMessage: null },
        { scanner: 'trivy', status: 'FAILED', toolVersion: '0.76.1', rulesetVersion: null, durationMs: 900, findingsCount: 0, errorMessage: 'database missing' },
        { scanner: 'phpcs', status: 'NOT_APPLICABLE', toolVersion: null, rulesetVersion: null, durationMs: null, findingsCount: 0, errorMessage: 'no PHP file' },
      ], languages: ['java', 'typescript'], score: { security: null, quality: 88, global: null, coverage: 40,
        reliability: 'LOW', formulaVersion: '1', details: {}, computedAt: RUN.createdAt } }] });
    await fixture.whenStable();
    const job = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="job"]')!;
    expect(job.textContent).toContain('Opengrep : 2 résultat(s)');
    expect(job.textContent).toContain('Trivy : échec, résultats inconnus');
    expect(job.textContent).toContain('PHP_CodeSniffer : rien à analyser (aucun fichier PHP)');
    expect(Array.from(job.querySelectorAll('[data-testid="language"]')).map(x => x.textContent?.trim())).toEqual(['Java', 'TypeScript']);
    const scores = job.querySelector('[data-testid="scores"]')!.textContent!;
    expect(scores).toContain('Sécurité —');
    expect(scores).toContain('Qualité 88');
    expect(scores).toContain('couverture 40 %');
  });

  it('launches an audit of every selected repository', async () => {
    const fixture = render(['AUDITOR']);
    await fixture.whenStable();
    (fixture.nativeElement.querySelector('[data-testid="launch"]') as HTMLButtonElement).click();
    const req = http.expectOne(r => r.method === 'POST' && r.url === '/api/v1/scans');
    expect(req.request.body).toEqual({ allTargets: true });
    req.flush({ id: 'run2' });
    http.expectOne(r => r.url === '/api/v1/scans').flush({ items: [], page: 0, size: 20, totalElements: 0, totalPages: 0 });
    http.expectOne('/api/v1/scans/run2').flush({ run: { ...RUN, id: 'run2', status: 'QUEUED', planned: false }, jobs: [], planningNotes: [] });
  });
});
