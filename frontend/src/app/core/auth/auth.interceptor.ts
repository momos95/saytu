import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { AppConfigService } from '../config/app-config';
import { isApiCall } from './api-url';
import { AuthService } from './auth.service';

/**
 * Adds the access token to calls to our own API only: the token must never be sent to another
 * origin (runtime config, third-party URLs). A 401 means the session is over: back to sign-in.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const apiBase = inject(AppConfigService).config().apiBaseUrl;
  if (!isApiCall(req.url, apiBase)) {
    return next(req);
  }
  const auth = inject(AuthService);
  const router = inject(Router);
  return from(auth.accessToken()).pipe(
    switchMap(token => next(token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req)),
    catchError((error: unknown) => {
      if (error instanceof HttpErrorResponse && error.status === 401) {
        auth.invalidate();
        void auth.login(router.url);
      }
      return throwError(() => error);
    }),
  );
};
