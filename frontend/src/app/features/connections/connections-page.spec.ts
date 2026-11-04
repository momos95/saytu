import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth/auth.service';
import { fakeTokens } from '../../testing/fake-session';
import { ConnectionsPage } from './connections-page';
import { GitConnection } from './connections.model';

const connection: GitConnection = {
  id: 'c1',
  name: 'GitLab Corp',
  providerType: 'GITLAB',
  baseUrl: 'https://gitlab.corp.sn',
  apiUrl: null,
  username: null,
  hasToken: true,
  enabled: true,
  lastTest: { status: 'AUTHENTICATION_FAILED', message: 'Token rejected', authenticatedAs: null, serverVersion: null,
    warnings: [], testedAt: '2026-11-04T10:00:00Z' },
  tokenExpiresAt: null,
  createdBy: 'admin',
  createdAt: '2026-11-01T10:00:00Z',
  updatedAt: '2026-11-01T10:00:00Z',
  version: 0,
};

describe('ConnectionsPage', () => {
  let controller: HttpTestingController;

  function render(roles: ('ADMIN' | 'AUDITOR' | 'VIEWER')[]) {
    TestBed.configureTestingModule({
      imports: [ConnectionsPage],
      providers: [provideZonelessChangeDetection(), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(roles));
    controller = TestBed.inject(HttpTestingController);
    return TestBed.createComponent(ConnectionsPage);
  }

  afterEach(() => controller.verify());

  it('lists connections with their last test status, never a token', async () => {
    const fixture = render(['ADMIN']);
    fixture.detectChanges();
    controller.expectOne('/api/v1/git-connections').flush([connection]);
    await fixture.whenStable();
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('GitLab Corp');
    expect(text).toContain('Authentification refusée');
    expect(text).toContain('Token enregistré (chiffré)');
    expect(text).toContain('Nouvelle connexion');
  });

  it('hides management actions from viewers', async () => {
    const fixture = render(['VIEWER']);
    fixture.detectChanges();
    controller.expectOne('/api/v1/git-connections').flush([connection]);
    await fixture.whenStable();
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).not.toContain('Nouvelle connexion');
    expect(text).not.toContain('Supprimer');
  });

  it('tests a connection and shows the result', async () => {
    const fixture = render(['ADMIN']);
    fixture.detectChanges();
    controller.expectOne('/api/v1/git-connections').flush([connection]);
    await fixture.whenStable();
    const testButton = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('button'))
      .find(b => b.textContent?.trim() === 'Tester') as HTMLButtonElement;
    testButton.click();
    controller.expectOne(r => r.method === 'POST' && r.url === '/api/v1/git-connections/c1/test').flush({
      success: true, status: 'OK', message: null, authenticatedAs: 'awa', serverVersion: '17.11', grantedScopes: ['read_api'],
      warnings: ['Token expires in 3 days'], tokenExpiresAt: null, testedAt: '2026-11-04T10:00:00Z',
    });
    controller.expectOne('/api/v1/git-connections').flush([connection]);
    await fixture.whenStable();
    const result = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="test-result"]');
    expect(result?.textContent).toContain('Connexion réussie');
    expect(result?.textContent).toContain('Token expires in 3 days');
  });
});
