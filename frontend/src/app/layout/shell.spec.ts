import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { NAV_ITEMS, routes } from '../app.routes';
import { Shell } from './shell';

describe('Shell', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [Shell],
      providers: [provideZonelessChangeDetection(), provideRouter(routes)],
    });
  });

  it('lists every planned page in the navigation', async () => {
    const fixture = TestBed.createComponent(Shell);
    await fixture.whenStable();
    const links = fixture.nativeElement.querySelectorAll('nav a') as NodeListOf<HTMLAnchorElement>;
    expect(links.length).toBe(NAV_ITEMS.length);
    expect(links[0].textContent).toContain('Tableau de bord');
  });

  it('toggles the mobile menu', async () => {
    const fixture = TestBed.createComponent(Shell);
    await fixture.whenStable();
    const button = fixture.nativeElement.querySelector('.menu-toggle') as HTMLButtonElement;
    button.click();
    await fixture.whenStable();
    expect(button.getAttribute('aria-expanded')).toBe('true');
    expect((fixture.nativeElement.querySelector('nav') as HTMLElement).classList).toContain('open');
  });

  it('routes to a placeholder that states the delivery phase', async () => {
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/connections');
    const badge = harness.routeNativeElement?.querySelector('[data-testid="phase-badge"]');
    expect(badge?.textContent).toContain('Phase 2');
  });

  it('redirects unknown URLs to the dashboard', async () => {
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/does-not-exist');
    expect(harness.routeNativeElement?.textContent).toContain('Tableau de bord');
  });
});
