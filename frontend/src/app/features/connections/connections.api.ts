import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { AppConfigService } from '../../core/config/app-config';
import { ConnectionTest, GitConnection, GitConnectionRequest } from './connections.model';

@Injectable({ providedIn: 'root' })
export class ConnectionsApi {
  private readonly http = inject(HttpClient);
  private readonly config = inject(AppConfigService);

  private url(path = ''): string {
    return `${this.config.config().apiBaseUrl}/git-connections${path}`;
  }

  list(): Observable<GitConnection[]> {
    return this.http.get<GitConnection[]>(this.url());
  }

  create(request: GitConnectionRequest): Observable<GitConnection> {
    return this.http.post<GitConnection>(this.url(), request);
  }

  update(id: string, request: GitConnectionRequest): Observable<GitConnection> {
    return this.http.put<GitConnection>(this.url(`/${encodeURIComponent(id)}`), request);
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(this.url(`/${encodeURIComponent(id)}`));
  }

  test(id: string): Observable<ConnectionTest> {
    return this.http.post<ConnectionTest>(this.url(`/${encodeURIComponent(id)}/test`), null);
  }

  testDraft(request: GitConnectionRequest): Observable<ConnectionTest> {
    return this.http.post<ConnectionTest>(this.url('/test'), request);
  }
}

/** Human-readable message from an RFC 9457 problem response. */
export function errorMessage(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    const detail = (error.error as { detail?: string; errors?: unknown } | null)?.detail;
    if (detail) {
      return detail;
    }
    if (error.status === 0) {
      return 'Le serveur SAYTU est injoignable.';
    }
    if (error.status === 403) {
      return 'Action réservée aux administrateurs.';
    }
    return `Erreur ${error.status}.`;
  }
  return 'Erreur inattendue.';
}
