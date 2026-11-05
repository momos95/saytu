import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { AppConfigService } from '../../core/config/app-config';
import { PageView } from '../repositories/sources.model';
import { FindingPage, ScanRun, ScanRunDetail } from './audits.model';

export interface FindingQuery {
  repositoryId?: string;
  branch?: string;
  severity?: string[];
  status?: string[];
  scanner?: string;
  q?: string;
}

@Injectable({ providedIn: 'root' })
export class AuditsApi {
  private readonly http = inject(HttpClient);
  private readonly config = inject(AppConfigService);

  private url(path: string): string {
    return `${this.config.config().apiBaseUrl}${path}`;
  }

  runs(page = 0, size = 20): Observable<PageView<ScanRun>> {
    const params = new HttpParams().set('page', page).set('size', size);
    return this.http.get<PageView<ScanRun>>(this.url('/scans'), { params });
  }

  run(id: string): Observable<ScanRunDetail> {
    return this.http.get<ScanRunDetail>(this.url(`/scans/${encodeURIComponent(id)}`));
  }

  /** Every repository selected for audit, or the given repositories. */
  request(body: { allTargets: boolean; repositoryIds?: string[] }): Observable<{ id: string }> {
    return this.http.post<{ id: string }>(this.url('/scans'), body);
  }

  cancel(id: string): Observable<ScanRunDetail> {
    return this.http.post<ScanRunDetail>(this.url(`/scans/${encodeURIComponent(id)}/cancel`), null);
  }

  findings(query: FindingQuery, page = 0, size = 50): Observable<FindingPage> {
    let params = new HttpParams().set('page', page).set('size', size);
    if (query.repositoryId) {
      params = params.set('repositoryId', query.repositoryId);
    }
    if (query.branch) {
      params = params.set('branch', query.branch);
    }
    for (const s of query.severity ?? []) {
      params = params.append('severity', s);
    }
    for (const s of query.status ?? []) {
      params = params.append('status', s);
    }
    if (query.scanner) {
      params = params.set('scanner', query.scanner);
    }
    if (query.q) {
      params = params.set('q', query.q);
    }
    return this.http.get<FindingPage>(this.url('/findings'), { params });
  }
}
