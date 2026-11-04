import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { routes } from '../app.routes';
import { AuthService } from '../core/auth/auth.service';
import { NAV_ITEMS } from '../navigation';
import { fakeTokens } from '../testing/fake-session';
import { Shell } from './shell';

describe('Shell', () => {
  let auth: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [Shell],
      providers: [provideZonelessChangeDetection(), provideRouter(routes), provideHttpClient(), provideHttpClientTesting()],
    });
    auth = TestBed.inject(AuthService);
    auth.setTokensForTesting(fakeTokens(['ADMIN', 'AUDITOR', 'VIEWER']));
  });

  it('lists every page and shows the signed-in user with roles', async () => {
    const fixture = TestBed.createComponent(Shell);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('nav a').length).toBe(NAV_ITEMS.length);
    expect(el.querySelector('[data-testid="user-name"]')?.textContent).toContain('Awa Diop');
    expect(el.textContent).toContain('ADMIN');
  });

  it('toggles the mobile menu', async () => {
    const fixture = TestBed.createComponent(Shell);
    await fixture.whenStable();
    const button = fixture.nativeElement.querySelector('.menu-toggle') as HTMLButtonElement;
    button.click();
    await fixture.whenStable();
    expect(button.getAttribute('aria-expanded')).toBe('true');
  });

  it('routes pages not delivered yet to a placeholder stating their phase', async () => {
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/repositories');
    expect(harness.routeNativeElement?.querySelector('[data-testid="phase-badge"]')?.textContent).toContain('Phase 3');
  });

  it('starts sign-in instead of rendering protected pages when signed out', async () => {
    auth.setTokensForTesting(null);
    const login = spyOn(auth, 'login').and.resolveTo();
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/findings');
    expect(login).toHaveBeenCalledWith('/findings');
  });
});
