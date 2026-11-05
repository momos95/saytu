import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth/auth.service';
import { fakeTokens } from '../../testing/fake-session';
import { ScanSettingsPage } from './scan-settings-page';

describe('ScanSettingsPage', () => {
  let http: HttpTestingController;

  function render() {
    TestBed.configureTestingModule({
      imports: [ScanSettingsPage],
      providers: [provideZonelessChangeDetection(), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(['ADMIN']));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ScanSettingsPage);
    fixture.detectChanges();
    http.expectOne('/api/v1/scanners').flush([{ id: 'trivy', enabled: true, timeoutSeconds: 900, cpuSeconds: 1800,
      memoryMb: 2048, optional: false, producedTypes: ['DEPENDENCY'], languages: [], settings: {}, settingKeys: [],
      updatedBy: null, updatedAt: '2026-11-04T10:00:00Z' },
    { id: 'phpcs', enabled: true, timeoutSeconds: 900, cpuSeconds: 900, memoryMb: 1024, optional: false,
      producedTypes: ['QUALITY'], languages: ['php'], settings: { standard: 'PSR12' }, settingKeys: ['standard'],
      updatedBy: null, updatedAt: '2026-11-04T10:00:00Z' }]);
    http.expectOne('/api/v1/scan-targets/summary').flush({ selectedNamespaces: 1, repositories: 1, defaultBranchMode: 1,
      presetBranchMode: 0, customBranchMode: 0 });
    http.expectOne(r => r.url === '/api/v1/repositories/targets').flush({ page: 0, size: 50, totalElements: 1, totalPages: 1,
      items: [{ id: 'r1', connectionId: 'c1', connectionName: 'GitLab', namespaceId: 'n1', namespacePath: 'acme',
        fullName: 'acme/api', name: 'api', webUrl: null, defaultBranch: 'main', visibility: 'PRIVATE', archived: false,
        removed: false, selected: true, scanTarget: true, branchMode: 'DEFAULT', branches: [], lastActivityAt: null,
        languages: ['java'] }] });
    return fixture;
  }

  afterEach(() => http.verify());

  it('shows scope, scanners and targets', async () => {
    const fixture = render();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="summary"]')?.textContent).toContain('dépôts audités');
    expect(el.querySelector('[data-testid="scanner"]')?.textContent).toContain('Trivy');
    expect(el.querySelector('[data-testid="target"]')?.textContent).toContain('→ main');
  });

  it('saves scanner changes', async () => {
    const fixture = render();
    await fixture.whenStable();
    const box = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="scanner"] input[type=checkbox]') as HTMLInputElement;
    box.click();
    const req = http.expectOne(r => r.method === 'PUT' && r.url === '/api/v1/scanners/trivy');
    expect(req.request.body.enabled).toBeFalse();
    req.flush({ id: 'trivy', enabled: false, timeoutSeconds: 900, cpuSeconds: 1800, memoryMb: 2048, optional: false,
      producedTypes: [], languages: [], settings: {}, settingKeys: [], updatedBy: 'awa', updatedAt: '2026-11-04T10:00:00Z' });
  });

  it('shows the language of a quality tool and saves its options', async () => {
    const fixture = render();
    await fixture.whenStable();
    const card = (fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="scanner"]')[1];
    expect(card.textContent).toContain('PHP_CodeSniffer');
    expect(card.textContent).toContain('contient du PHP');
    const field = card.querySelector('input.setting') as HTMLInputElement;
    expect(field.value).toBe('PSR12');
    field.value = 'PSR2';
    field.dispatchEvent(new Event('change'));
    const req = http.expectOne(r => r.method === 'PUT' && r.url === '/api/v1/scanners/phpcs');
    expect(req.request.body.settings).toEqual({ standard: 'PSR2' });
    req.flush({ id: 'phpcs', enabled: true, timeoutSeconds: 900, cpuSeconds: 900, memoryMb: 1024, optional: false,
      producedTypes: ['QUALITY'], languages: ['php'], settings: { standard: 'PSR2' }, settingKeys: ['standard'],
      updatedBy: 'awa', updatedAt: '2026-11-05T10:00:00Z' });
  });
});
