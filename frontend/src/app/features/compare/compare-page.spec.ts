import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { AuthService } from '../../core/auth/auth.service';
import { fakeTokens } from '../../testing/fake-session';
import { ComparePage } from './compare-page';

const JOB = { id: 'j2', repositoryId: 'r1', repository: 'acme/api', branch: 'main', status: 'SUCCEEDED', commitSha: 'b'.repeat(40),
  finishedAt: '2026-11-08T10:00:00Z', score: null };

describe('ComparePage', () => {
  it('shows introduced, fixed and unverifiable findings', async () => {
    TestBed.configureTestingModule({
      providers: [provideZonelessChangeDetection(), provideHttpClient(), provideHttpClientTesting(),
        provideRouter([{ path: 'compare', component: ComparePage }])],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(['VIEWER']));
    const http = TestBed.inject(HttpTestingController);
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/compare?head=j2');
    http.expectOne(r => r.url === '/api/v1/jobs/j2/compare' && !r.params.has('with')).flush({
      base: { ...JOB, id: 'j1', commitSha: 'a'.repeat(40) }, head: JOB, introduced: [], fixed: [], unverified: [],
      persisting: 4, introducedTotal: 0, fixedTotal: 2, unverifiedTotal: 1,
      scanners: [{ scanner: 'trivy', baseStatus: 'SUCCEEDED', headStatus: 'FAILED', baseVersion: '0.76.1', headVersion: '0.76.1' }],
    });
    await harness.fixture.whenStable();
    const el = harness.routeNativeElement!;
    expect(el.querySelector('[data-testid="fixed"]')?.textContent).toContain('2');
    expect(el.querySelector('[data-testid="unverified"]')?.textContent).toContain('1');
    expect(el.textContent).toContain('Non vérifiable');
    http.verify();
  });
});
