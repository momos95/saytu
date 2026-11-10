import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { fakeTokens } from '../../testing/fake-session';
import { DashboardPage } from './dashboard-page';

const zero = { SECURITY: 0, SECRET: 0, DEPENDENCY: 0, QUALITY: 0 };
const SCORE = { security: null, quality: 81, global: null, coverage: 35, reliability: 'INSUFFICIENT', formulaVersion: 'v1',
  details: {}, computedAt: '2026-11-06T09:00:00Z' };

function dashboard(audited: number) {
  return {
    global: audited ? SCORE : null,
    counters: { auditedRepositories: audited, openFindings: 7, newLast7Days: 7, resolvedLast7Days: 1, triaged: 2,
      lastAuditAt: '2026-11-06T09:00:00Z', workflowChecked: 4, workflowPass: 1, workflowFail: 2 },
    openBySeverity: { CRITICAL: { ...zero, SECRET: 1 }, HIGH: { ...zero, DEPENDENCY: 6 }, MEDIUM: zero, LOW: zero, INFO: zero },
    trend: [], weeklyFlow: [{ week: '2026-11-02T00:00:00Z', opened: 7, resolved: 1 }],
    priorities: [{ repositoryId: 'r1', repository: 'acme/api', languages: ['java'], critical: 1, high: 6, securityFindings: 7,
      openFindings: 7, score: SCORE, workflowStatus: 'WARN' }],
    recentRuns: [],
  };
}

describe('DashboardPage', () => {
  let http: HttpTestingController;

  function render(body: unknown) {
    TestBed.configureTestingModule({
      imports: [DashboardPage],
      providers: [provideZonelessChangeDetection(), provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(['VIEWER']));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(DashboardPage);
    fixture.detectChanges();
    http.expectOne('/api/v1/dashboard').flush(body);
    return fixture;
  }

  afterEach(() => http.verify());

  it('never shows a score that could not be computed', async () => {
    const fixture = render(dashboard(1));
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const cards = Array.from(el.querySelectorAll('[data-testid="score-card"]')).map(c => c.textContent ?? '');
    expect(cards[0]).toContain('—');
    expect(cards[0]).toContain('couverture insuffisante');
    expect(cards[2]).toContain('81');
    expect(el.querySelector('[data-testid="priority"]')?.textContent).toContain('1 critique(s)');
    expect(el.querySelector('[data-testid="priority"] [data-testid="workflow-badge"]')?.textContent).toContain('à surveiller');
    const wf = el.querySelector('[data-testid="workflow-kpi"]')!.textContent!;
    expect(wf).toContain('1 / 4');
    expect(wf).toContain('2 non conforme(s)');
    expect(el.textContent).toContain('vulnérabilités ouvertes');
  });

  it('explains what to do before the first audit', async () => {
    const fixture = render(dashboard(0));
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Aucun dépôt audité');
    expect(el.querySelector('[data-testid="score-card"]')).toBeNull();
  });
});
