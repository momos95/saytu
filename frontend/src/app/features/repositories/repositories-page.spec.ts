import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth/auth.service';
import { fakeTokens } from '../../testing/fake-session';
import { RepositoriesPage } from './repositories-page';
import { Namespace } from './sources.model';

function ns(id: string, fullPath: string, parentId: string | null, extra: Partial<Namespace> = {}): Namespace {
  return {
    id, connectionId: 'c1', externalId: id, kind: parentId ? 'SUBGROUP' : 'GROUP', fullPath, name: fullPath, parentId,
    webUrl: null, selected: false, includeAllRepositories: false, addedManually: false, removed: false,
    repositoriesSyncedAt: null, repositoriesSyncStatus: null, repositoriesSyncMessage: null, repositoriesTruncated: false,
    repositoryCount: 3, selectedRepositoryCount: 0, ...extra,
  };
}

describe('RepositoriesPage', () => {
  let http: HttpTestingController;

  function render(roles: ('ADMIN' | 'VIEWER')[]) {
    TestBed.configureTestingModule({
      imports: [RepositoriesPage],
      providers: [provideZonelessChangeDetection(), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).setTokensForTesting(fakeTokens(roles));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(RepositoriesPage);
    fixture.detectChanges();
    http.expectOne('/api/v1/git-connections').flush([{ id: 'c1', name: 'GitLab', enabled: true }]);
    http.expectOne('/api/v1/git-connections/c1/namespaces').flush([ns('2', 'acme/pay', '1'), ns('1', 'acme', null, { selected: true })]);
    return fixture;
  }

  afterEach(() => http.verify());

  it('shows namespaces as a tree with their counts', async () => {
    const fixture = render(['ADMIN']);
    await fixture.whenStable();
    const items = (fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="namespace"]');
    expect(items.length).toBe(2);
    expect(items[0].textContent).toContain('acme');
    expect(items[1].textContent).toContain('acme/pay');
    expect(items[0].textContent).toContain('Tous les dépôts');
  });

  it('runs a discovery and reports the outcome', async () => {
    const fixture = render(['ADMIN']);
    await fixture.whenStable();
    const button = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('button'))
      .find(b => b.textContent?.includes('Découvrir')) as HTMLButtonElement;
    button.click();
    http.expectOne(r => r.method === 'POST' && r.url === '/api/v1/git-connections/c1/discovery')
      .flush({ status: 'OK', message: null, found: 2, added: 1, removed: 0, truncated: false, retryAfterSeconds: null });
    http.expectOne('/api/v1/git-connections/c1/namespaces').flush([]);
    await fixture.whenStable();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="discovery-message"]')?.textContent)
      .toContain('2 trouvé(s)');
  });

  it('is read-only for viewers', async () => {
    const fixture = render(['VIEWER']);
    await fixture.whenStable();
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).not.toContain('Découvrir les organisations');
    expect(text).not.toContain('Charger les dépôts');
    const box = (fixture.nativeElement as HTMLElement).querySelector('input[type=checkbox]') as HTMLInputElement;
    expect(box.disabled).toBeTrue();
  });
});
