import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { AppRole } from '../../core/auth/oidc';
import { fakeTokens } from '../../testing/fake-session';
import { SettingsPage } from './settings-page';

const SCHEDULE = { id: 's1', name: 'Nuit', cronExpression: '0 0 2 * * *', timeZone: 'Europe/Paris', scope: 'ALL_SELECTED',
  enabled: true, nextFireAt: '2026-11-09T01:00:00Z', lastFiredAt: null, lastRunId: null, lastRunStatus: null, lastOutcome: null,
  repositoryIds: [], namespaceIds: [], createdBy: 'awa', createdAt: '2026-11-08T10:00:00Z', updatedAt: '2026-11-08T10:00:00Z' };

describe('SettingsPage', () => {
  let http: HttpTestingController;

  function render(roles: AppRole[]) {
    TestBed.configureTestingModule({
      imports: [SettingsPage],
      providers: [provideZonelessChangeDetection(), provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(roles));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(SettingsPage);
    fixture.detectChanges();
    http.expectOne('/api/v1/schedules').flush([SCHEDULE]);
    return fixture;
  }

  afterEach(() => http.verify());

  it('shows schedules in plain French and hides administration from viewers', async () => {
    const fixture = render(['VIEWER']);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="schedule"]')?.textContent).toContain('chaque jour à 2 h');
    expect(el.querySelector('[data-testid="schedule-form"]')).toBeNull();
    (el.querySelector('[data-tab="webhooks"]') as HTMLButtonElement).click();
    await fixture.whenStable();
    expect(el.textContent).toContain('Réservé aux administrateurs');
  });

  it('creates a schedule and explains how to enable user management', async () => {
    const fixture = render(['ADMIN']);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const name = el.querySelector('[data-testid="schedule-form"] input') as HTMLInputElement;
    name.value = 'Semaine';
    name.dispatchEvent(new Event('input'));
    (Array.from(el.querySelectorAll('button')).find(b => b.textContent?.includes('Enregistrer')) as HTMLButtonElement).click();
    const req = http.expectOne(r => r.method === 'POST' && r.url === '/api/v1/schedules');
    expect(req.request.body.name).toBe('Semaine');
    expect(req.request.body.cronExpression).toBe('0 2 * * *');
    expect(req.request.body.scope).toBe('ALL_SELECTED');
    req.flush({ ...SCHEDULE, id: 's2', name: 'Semaine' });
    http.expectOne('/api/v1/schedules').flush([SCHEDULE]);

    (el.querySelector('[data-tab="users"]') as HTMLButtonElement).click();
    http.expectOne('/api/v1/users/status').flush({ configured: false, message: 'Non configuré : lancer scripts/keycloak-admin-client.ps1' });
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="users-not-configured"]')?.textContent).toContain('keycloak-admin-client');
  });
});
