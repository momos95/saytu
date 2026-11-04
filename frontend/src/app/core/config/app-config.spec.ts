import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AppConfigService, DEFAULT_CONFIG } from './app-config';

describe('AppConfigService', () => {
  let service: AppConfigService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideZonelessChangeDetection(), provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AppConfigService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('loads the runtime configuration and strips trailing slashes', async () => {
    const done = service.load();
    http.expectOne('/assets/config.json').flush({
      oidcIssuer: 'https://sso.example.org/realms/saytu/',
      oidcClientId: 'web',
      apiBaseUrl: '/api/v1',
    });
    await done;
    expect(service.config().oidcIssuer).toBe('https://sso.example.org/realms/saytu');
    expect(service.config().oidcClientId).toBe('web');
  });

  it('falls back to defaults when the file is missing', async () => {
    const done = service.load();
    http.expectOne('/assets/config.json').flush('not found', { status: 404, statusText: 'Not Found' });
    await done;
    expect(service.config()).toEqual(DEFAULT_CONFIG);
  });

  it('ignores empty values and unsubstituted placeholders', () => {
    const merged = AppConfigService.merge({ oidcIssuer: '${SAYTU_OIDC_ISSUER}', oidcClientId: '  ' });
    expect(merged).toEqual(DEFAULT_CONFIG);
  });
});
