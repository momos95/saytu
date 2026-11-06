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
    });
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('h1')?.textContent).toContain('acme/api');
    expect(el.textContent).toContain('GitLab');
    expect(el.querySelector('[data-testid="branch"]')?.textContent).toContain('pas encore de score');
    const audit = Array.from(el.querySelectorAll('button')).find(b => b.textContent?.includes('Auditer ce dépôt')) as HTMLButtonElement;
    audit.click();
    const req = http.expectOne(r => r.method === 'POST' && r.url === '/api/v1/scans');
    expect(req.request.body).toEqual({ allTargets: false, repositoryIds: ['r1'] });
    req.flush({ id: 'run9' });
    http.verify();
  });
});
