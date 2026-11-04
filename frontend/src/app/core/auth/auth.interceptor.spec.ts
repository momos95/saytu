import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { fakeTokens } from '../../testing/fake-session';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';

describe('authInterceptor', () => {
  let http: HttpClient;
  let controller: HttpTestingController;
  let auth: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        provideRouter([]),
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    http = TestBed.inject(HttpClient);
    controller = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
    auth.setTokensForTesting(fakeTokens(['VIEWER']));
  });

  afterEach(() => controller.verify());

  /** The interceptor awaits accessToken() before sending: let that microtask run. */
  const flushMicrotasks = () => new Promise(resolve => setTimeout(resolve));

  it('adds the bearer token to API calls', async () => {
    const done = firstValueFrom(http.get('/api/v1/git-connections'));
    await flushMicrotasks();
    const req = controller.expectOne('/api/v1/git-connections');
    expect(req.request.headers.get('Authorization')).toMatch(/^Bearer .+\..+\..+$/);
    req.flush([]);
    await done;
  });

  it('never sends the token to other URLs', async () => {
    const done = firstValueFrom(http.get('/assets/config.json'));
    await flushMicrotasks();
    const req = controller.expectOne('/assets/config.json');
    expect(req.request.headers.has('Authorization')).toBeFalse();
    req.flush({});
    await done;
  });

  it('restarts sign-in on 401', async () => {
    const login = spyOn(auth, 'login').and.resolveTo();
    const done = firstValueFrom(http.get('/api/v1/system/info')).catch(e => e);
    await flushMicrotasks();
    controller.expectOne('/api/v1/system/info').flush({}, { status: 401, statusText: 'Unauthorized' });
    await done;
    expect(auth.isAuthenticated()).toBeFalse();
    expect(login).toHaveBeenCalled();
  });
});
