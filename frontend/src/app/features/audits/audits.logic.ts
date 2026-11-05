import { ExecutionStatus, Finding, RunStatus, ScanRun, ScannerExecution } from './audits.model';

export const RUN_STATUS_LABELS: Record<RunStatus, string> = {
  QUEUED: 'En attente',
  RUNNING: 'En cours',
  SUCCEEDED: 'Terminé',
  PARTIAL: 'Terminé partiellement',
  FAILED: 'Échec',
  CANCELLED: 'Annulé',
};

export const EXECUTION_STATUS_LABELS: Record<ExecutionStatus, string> = {
  SUCCEEDED: 'exécuté',
  FAILED: 'échec',
  TIMED_OUT: 'délai dépassé',
  SKIPPED: 'non exécuté',
  NOT_APPLICABLE: 'rien à analyser',
};

export const SHORT_SCANNER_LABELS: Record<string, string> = {
  opengrep: 'Opengrep',
  trivy: 'Trivy',
  gitleaks: 'Gitleaks',
  pmd: 'PMD',
  checkstyle: 'Checkstyle',
  'dependency-check': 'Dependency-Check',
};

export const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: 'Critique',
  HIGH: 'Élevée',
  MEDIUM: 'Moyenne',
  LOW: 'Faible',
  INFO: 'Info',
};

export function isActive(run: Pick<ScanRun, 'status'>): boolean {
  return run.status === 'QUEUED' || run.status === 'RUNNING';
}

/** "3 / 5 analyses" with the planning phase made explicit. */
export function progress(run: ScanRun): string {
  if (!run.planned) {
    return run.status === 'CANCELLED' ? '—' : 'préparation…';
  }
  if (run.totalJobs === 0) {
    return 'aucune branche';
  }
  return `${run.finishedJobs} / ${run.totalJobs} branche(s)`;
}

export function scopeLabel(scope: string | null): string {
  if (!scope) {
    return '';
  }
  if (scope === 'ALL_TARGETS') {
    return 'tous les dépôts sélectionnés';
  }
  const n = parseInt(scope, 10);
  return Number.isNaN(n) ? scope : `${n} dépôt(s)`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) {
    return '';
  }
  if (ms < 1000) {
    return `${ms} ms`;
  }
  const s = Math.round(ms / 1000);
  if (s < 60) {
    return `${s} s`;
  }
  const m = Math.floor(s / 60);
  return `${m} min ${String(s % 60).padStart(2, '0')} s`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) {
    return '';
  }
  const units = ['o', 'Ko', 'Mo', 'Go'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Elapsed time between two ISO instants (or until now), e.g. "2 min 05 s". */
export function elapsed(from: string | null, to: string | null, now = Date.now()): string {
  if (!from) {
    return '';
  }
  const end = to ? Date.parse(to) : now;
  return formatDuration(Math.max(0, end - Date.parse(from)));
}

/**
 * One-line explanation of a scanner execution. A scanner that did not succeed is never presented as
 * "no finding": the reason is shown instead.
 */
export function describeExecution(e: ScannerExecution): string {
  const name = SHORT_SCANNER_LABELS[e.scanner] ?? e.scanner;
  switch (e.status) {
    case 'SUCCEEDED':
      return `${name} : ${e.findingsCount} résultat(s)`;
    case 'NOT_APPLICABLE':
      return `${name} : rien à analyser`;
    case 'SKIPPED':
      return `${name} : non exécuté${e.errorMessage ? ` (${e.errorMessage})` : ''}`;
    case 'TIMED_OUT':
      return `${name} : délai dépassé, résultats inconnus`;
    case 'FAILED':
      return e.findingsCount > 0
        ? `${name} : analyse incomplète, ${e.findingsCount} résultat(s) partiel(s)`
        : `${name} : échec, résultats inconnus`;
  }
}

export function executionTone(status: ExecutionStatus): 'ok' | 'warn' | 'muted' {
  switch (status) {
    case 'SUCCEEDED':
      return 'ok';
    case 'NOT_APPLICABLE':
    case 'SKIPPED':
      return 'muted';
    default:
      return 'warn';
  }
}

export function location(f: Pick<Finding, 'filePath' | 'startLine' | 'packageName' | 'packageVersion'>): string {
  if (f.packageName) {
    return `${f.packageName}${f.packageVersion ? '@' + f.packageVersion : ''}${f.filePath ? ' — ' + f.filePath : ''}`;
  }
  if (!f.filePath) {
    return '';
  }
  return f.startLine ? `${f.filePath}:${f.startLine}` : f.filePath;
}

export function shortSha(sha: string | null): string {
  return sha ? sha.substring(0, 8) : '';
}
