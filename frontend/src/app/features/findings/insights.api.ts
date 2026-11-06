import { HttpClient, HttpParams, HttpResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { AppConfigService } from '../../core/config/app-config';
import { FindingPage } from '../audits/audits.model';
import { fileNameFrom, filtersToHttpPairs } from './insights.logic';
import { Dashboard, FindingDetail, FindingFilters, ReportFormat, RepositoryOverview } from './insights.model';

export interface DownloadedReport {
  fileName: string;
  blob: Blob;
}

@Injectable({ providedIn: 'root' })
export class InsightsApi {
  private readonly http = inject(HttpClient);
  private readonly config = inject(AppConfigService);

  private url(path: string): string {
    return `${this.config.config().apiBaseUrl}${path}`;
  }

  private params(filters: FindingFilters): HttpParams {
    let params = new HttpParams();
    for (const [k, v] of filtersToHttpPairs(filters)) {
      params = params.append(k, v);
    }
    return params;
  }

  dashboard(): Observable<Dashboard> {
    return this.http.get<Dashboard>(this.url('/dashboard'));
  }

  repository(id: string): Observable<RepositoryOverview> {
    return this.http.get<RepositoryOverview>(this.url(`/repositories/${encodeURIComponent(id)}/overview`));
  }

  findings(filters: FindingFilters, page = 0, size = 50): Observable<FindingPage> {
    const params = this.params(filters).set('page', page).set('size', size);
    return this.http.get<FindingPage>(this.url('/findings'), { params });
  }

  finding(id: string): Observable<FindingDetail> {
    return this.http.get<FindingDetail>(this.url(`/findings/${encodeURIComponent(id)}`));
  }

  changeStatus(id: string, status: string, reason: string | null): Observable<FindingDetail> {
    return this.http.put<FindingDetail>(this.url(`/findings/${encodeURIComponent(id)}/status`), { status, reason });
  }

  /** Report as a file: the token is sent by the interceptor, so a plain link would not work. */
  report(format: ReportFormat, filters: FindingFilters): Observable<DownloadedReport> {
    const params = this.params(filters).set('format', format);
    return this.http.get(this.url('/reports/findings'), { params, responseType: 'blob', observe: 'response' }).pipe(
      map((res: HttpResponse<Blob>) => ({
        fileName: fileNameFrom(res.headers.get('Content-Disposition'), `saytu-report.${format}`),
        blob: res.body ?? new Blob(),
      })));
  }
}
