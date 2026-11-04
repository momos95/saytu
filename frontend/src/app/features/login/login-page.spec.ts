import { provideHttpClient } from '@angular/common/http';
import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth/auth.service';
import { LoginPage } from './login-page';

describe('LoginPage', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [provideZonelessChangeDetection(), provideHttpClient()],
    });
  });

  it('explains known errors in French', async () => {
    const fixture = TestBed.createComponent(LoginPage);
    fixture.componentRef.setInput('error', 'state_mismatch');
    await fixture.whenStable();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="login-error"]')?.textContent)
      .toContain('ne correspond pas');
  });

  it('starts the Keycloak redirect with a safe return URL', async () => {
    const auth = TestBed.inject(AuthService);
    const login = spyOn(auth, 'login').and.resolveTo();
    const fixture = TestBed.createComponent(LoginPage);
    fixture.componentRef.setInput('returnUrl', 'https://evil.example');
    await fixture.whenStable();
    (fixture.nativeElement.querySelector('button') as HTMLButtonElement).click();
    expect(login).toHaveBeenCalledWith('/');
  });
});
