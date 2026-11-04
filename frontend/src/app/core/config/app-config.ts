import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

/**
 * Runtime configuration, served by nginx at /assets/config.json and generated from environment
 * variables at container start. One image works for every installation: no rebuild per site.
 */
export interface AppConfig {
  /** OIDC issuer, e.g. https://sso.example.org/realms/saytu */
  oidcIssuer: string;
  /** Keycloak public client of the SPA */
  oidcClientId: string;
  /** Base path of the REST API (same origin, proxied by nginx) */
  apiBaseUrl: string;
}

export const DEFAULT_CONFIG: AppConfig = {
  oidcIssuer: 'http://localhost:8180/realms/saytu',
  oidcClientId: 'saytu-web',
  apiBaseUrl: '/api/v1',
};

@Injectable({ providedIn: 'root' })
export class AppConfigService {
  private readonly http = inject(HttpClient);
  private readonly current = signal<AppConfig>(DEFAULT_CONFIG);

  readonly config = this.current.asReadonly();

  /** Called once at bootstrap. Invalid or missing files fall back to defaults, never block the UI. */
  async load(url = '/assets/config.json'): Promise<void> {
    try {
      const loaded = await firstValueFrom(this.http.get<Partial<AppConfig>>(url));
      this.current.set(AppConfigService.merge(loaded));
    } catch {
      console.warn(`SAYTU: ${url} unavailable, using default configuration`);
    }
  }

  static merge(loaded: Partial<AppConfig> | null | undefined): AppConfig {
    const result: AppConfig = { ...DEFAULT_CONFIG };
    if (!loaded) {
      return result;
    }
    for (const key of Object.keys(DEFAULT_CONFIG) as (keyof AppConfig)[]) {
      const value = loaded[key];
      // ignore empty strings and un-substituted ${VAR} placeholders
      if (typeof value === 'string' && value.trim() !== '' && !value.includes('${')) {
        result[key] = value.trim().replace(/\/+$/, '');
      }
    }
    return result;
  }
}
