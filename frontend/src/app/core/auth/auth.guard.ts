import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AppRole } from './oidc';
import { AuthService } from './auth.service';

/** Signed-in users only; others are sent to Keycloak and come back to the requested page. */
export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(AuthService);
  if (auth.isAuthenticated()) {
    return true;
  }
  void auth.login(state.url);
  return false;
};

/** Pages reserved to some roles: others land on the dashboard (the API enforces it anyway). */
export function roleGuard(...roles: AppRole[]): CanActivateFn {
  return () => {
    const auth = inject(AuthService);
    return roles.some(r => auth.hasRole(r)) ? true : inject(Router).createUrlTree(['/dashboard']);
  };
}
