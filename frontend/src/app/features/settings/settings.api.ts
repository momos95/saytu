import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { AppConfigService } from '../../core/config/app-config';
import { AiSettings, AiTest, AppUser, Credentials, Delivery, Schedule, ScheduleRequest, TestResult, UserStatus, Webhook,
  WebhookRequest } from './settings.model';

@Injectable({ providedIn: 'root' })
export class SettingsApi {
  private readonly http = inject(HttpClient);
  private readonly config = inject(AppConfigService);

  private url(path: string): string {
    return `${this.config.config().apiBaseUrl}${path}`;
  }

  schedules(): Observable<Schedule[]> {
    return this.http.get<Schedule[]>(this.url('/schedules'));
  }

  saveSchedule(id: string | null, r: ScheduleRequest): Observable<Schedule> {
    return id ? this.http.put<Schedule>(this.url(`/schedules/${id}`), r) : this.http.post<Schedule>(this.url('/schedules'), r);
  }

  deleteSchedule(id: string): Observable<void> {
    return this.http.delete<void>(this.url(`/schedules/${id}`));
  }

  webhooks(): Observable<Webhook[]> {
    return this.http.get<Webhook[]>(this.url('/webhooks'));
  }

  saveWebhook(id: string | null, r: WebhookRequest): Observable<Webhook> {
    return id ? this.http.put<Webhook>(this.url(`/webhooks/${id}`), r) : this.http.post<Webhook>(this.url('/webhooks'), r);
  }

  deleteWebhook(id: string): Observable<void> {
    return this.http.delete<void>(this.url(`/webhooks/${id}`));
  }

  testWebhook(id: string): Observable<TestResult> {
    return this.http.post<TestResult>(this.url(`/webhooks/${id}/test`), {});
  }

  deliveries(id: string): Observable<Delivery[]> {
    return this.http.get<Delivery[]>(this.url(`/webhooks/${id}/deliveries`));
  }

  userStatus(): Observable<UserStatus> {
    return this.http.get<UserStatus>(this.url('/users/status'));
  }

  users(): Observable<AppUser[]> {
    return this.http.get<AppUser[]>(this.url('/users'));
  }

  createUser(u: { username: string; email: string; firstName: string; lastName: string; role: string }): Observable<Credentials> {
    return this.http.post<Credentials>(this.url('/users'), u);
  }

  changeRole(id: string, role: string): Observable<AppUser> {
    return this.http.put<AppUser>(this.url(`/users/${id}/role`), { role });
  }

  setEnabled(id: string, enabled: boolean): Observable<AppUser> {
    return this.http.put<AppUser>(this.url(`/users/${id}/enabled`), { enabled });
  }

  resetPassword(id: string): Observable<Credentials> {
    return this.http.post<Credentials>(this.url(`/users/${id}/reset-password`), {});
  }

  ai(): Observable<AiSettings> {
    return this.http.get<AiSettings>(this.url('/settings/ai'));
  }

  saveAi(s: AiSettings): Observable<AiSettings> {
    return this.http.put<AiSettings>(this.url('/settings/ai'), s);
  }

  testAi(): Observable<AiTest> {
    return this.http.post<AiTest>(this.url('/settings/ai/test'), {});
  }
}
