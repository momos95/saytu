import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { AppConfigService } from '../../core/config/app-config';
import {
  BranchMode,
  DiscoveryResult,
  Namespace,
  PageView,
  RemoteBranches,
  Repository,
  ScanTargetSummary,
  Scanner,
} from './sources.model';

@Injectable({ providedIn: 'root' })
export class SourcesApi {
  private readonly http = inject(HttpClient);
  private readonly config = inject(AppConfigService);

  private url(path: string): string {
    return `${this.config.config().apiBaseUrl}${path}`;
  }

  private id(value: string): string {
    return encodeURIComponent(value);
  }

  namespaces(connectionId: string): Observable<Namespace[]> {
    return this.http.get<Namespace[]>(this.url(`/git-connections/${this.id(connectionId)}/namespaces`));
  }

  discoverNamespaces(connectionId: string): Observable<DiscoveryResult> {
    return this.http.post<DiscoveryResult>(this.url(`/git-connections/${this.id(connectionId)}/discovery`), null);
  }

  addNamespace(connectionId: string, path: string): Observable<Namespace> {
    return this.http.post<Namespace>(this.url(`/git-connections/${this.id(connectionId)}/namespaces`), { path });
  }

  selectNamespace(namespaceId: string, selected: boolean, includeAllRepositories: boolean): Observable<Namespace> {
    return this.http.put<Namespace>(this.url(`/namespaces/${this.id(namespaceId)}/selection`),
      { selected, includeAllRepositories });
  }

  discoverRepositories(namespaceId: string): Observable<DiscoveryResult> {
    return this.http.post<DiscoveryResult>(this.url(`/namespaces/${this.id(namespaceId)}/discovery`), null);
  }

  repositories(namespaceId: string, query: string, page: number, size: number): Observable<PageView<Repository>> {
    let params = new HttpParams().set('page', page).set('size', size);
    if (query.trim()) {
      params = params.set('q', query.trim());
    }
    return this.http.get<PageView<Repository>>(this.url(`/namespaces/${this.id(namespaceId)}/repositories`), { params });
  }

  scanTargets(query: string, page: number, size: number): Observable<PageView<Repository>> {
    let params = new HttpParams().set('page', page).set('size', size);
    if (query.trim()) {
      params = params.set('q', query.trim());
    }
    return this.http.get<PageView<Repository>>(this.url('/repositories/targets'), { params });
  }

  selectRepositories(repositoryIds: string[], selected: boolean): Observable<{ updated: number }> {
    return this.http.put<{ updated: number }>(this.url('/repositories/selection'), { repositoryIds, selected });
  }

  setBranchMode(repositoryIds: string[], mode: BranchMode): Observable<{ updated: number }> {
    return this.http.put<{ updated: number }>(this.url('/repositories/branch-mode'), { repositoryIds, mode });
  }

  setCustomBranches(repositoryId: string, branches: string[]): Observable<Repository> {
    return this.http.put<Repository>(this.url(`/repositories/${this.id(repositoryId)}/branches`), { branches });
  }

  remoteBranches(repositoryId: string): Observable<RemoteBranches> {
    return this.http.get<RemoteBranches>(this.url(`/repositories/${this.id(repositoryId)}/remote-branches`));
  }

  summary(): Observable<ScanTargetSummary> {
    return this.http.get<ScanTargetSummary>(this.url('/scan-targets/summary'));
  }

  scanners(): Observable<Scanner[]> {
    return this.http.get<Scanner[]>(this.url('/scanners'));
  }

  updateScanner(s: Pick<Scanner, 'id' | 'enabled' | 'timeoutSeconds' | 'cpuSeconds' | 'memoryMb'>): Observable<Scanner> {
    return this.http.put<Scanner>(this.url(`/scanners/${this.id(s.id)}`), {
      enabled: s.enabled, timeoutSeconds: s.timeoutSeconds, cpuSeconds: s.cpuSeconds, memoryMb: s.memoryMb,
    });
  }
}
