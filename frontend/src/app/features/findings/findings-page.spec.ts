import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { AuthService } from '../../core/auth/auth.service';
import { fakeTokens } from '../../testing/fake-session';
import { FindingsPage } from './findings-page';

const FINDING = { id: 'f1', repositoryId: 'r1', repositoryName: 'acme/api', branch: 'main', type: 'SECRET', severity: 'HIGH',
  scanner: 'gitleaks', ruleId: 'generic-api-key', title: 'Generic API key', filePath: 'src/app.yml', startLine: 3, endLine: 3,
  cwes: ['CWE-798'], cve: null, cvssScore: null, packageName: null, packageVersion: null, fixedVersion: null, status: 'OPEN',
  firstSeenAt: '2026-11-05T10:00:00Z', lastSeenAt: '2026-11-06T10:00:00Z', commitSha: null, scanners: ['gitleaks', 'opengrep'] };

describe('FindingsPage', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideZonelessChangeDetection(), provideHttpClient(), provideHttpClientTesting(),
        provideRouter([{ path: 'findings', component: FindingsPage }])],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(['VIEWER']));
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('opens on the open findings and keeps the filters in the URL', async () => {
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/findings');
    await harness.fixture.whenStable();
    const req = http.expectOne(r => r.url === '/api/v1/findings');
    expect(req.request.params.getAll('status')).toEqual(['OPEN']);
    req.flush({ page: { items: [FINDING], page: 0, size: 50, totalElements: 1, totalPages: 1 },
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 } });
    await harness.fixture.whenStable();
    const el = harness.routeNativeElement!;
    const row = el.querySelector('[data-testid="finding"]')!;
    expect(row.textContent).toContain('Generic API key');
    expect(row.textContent).toContain('Gitleaks, Opengrep');
    expect(row.textContent).toContain('src/app.yml:3');

    const high = Array.from(el.querySelectorAll('button.chip')).find(b => b.textContent?.includes('Élevée')) as HTMLButtonElement;
    high.click();
    await harness.fixture.whenStable();
    const filtered = http.expectOne(r => r.url === '/api/v1/findings');
    expect(filtered.request.params.getAll('severity')).toEqual(['HIGH']);
    expect(filtered.request.params.getAll('status')).toEqual(['OPEN']);
    filtered.flush({ page: { items: [], page: 0, size: 50, totalElements: 0, totalPages: 0 },
      bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } });
    await harness.fixture.whenStable();
    expect(el.textContent).toContain('Aucune vulnérabilité ne correspond');
  });
});
