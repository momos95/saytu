/** DTOs of /api/v1/scans and /api/v1/findings (see ScanViews.java). */

export type RunStatus = 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'PARTIAL' | 'FAILED' | 'CANCELLED';
export type ExecutionStatus = 'SUCCEEDED' | 'FAILED' | 'TIMED_OUT' | 'SKIPPED' | 'NOT_APPLICABLE';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface ScanRun {
  id: string;
  triggerType: string;
  requestedBy: string;
  status: RunStatus;
  totalJobs: number;
  finishedJobs: number;
  problemJobs: number;
  newFindings: number;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  planned: boolean;
  cancelRequested: boolean;
  errorMessage: string | null;
  scope: string | null;
}

export interface ScannerExecution {
  scanner: string;
  status: ExecutionStatus;
  toolVersion: string | null;
  rulesetVersion: string | null;
  durationMs: number | null;
  findingsCount: number;
  errorMessage: string | null;
}

export interface ScanJob {
  id: string;
  repositoryId: string;
  repositoryName: string;
  branch: string;
  commitSha: string | null;
  status: RunStatus;
  attempt: number;
  queuedAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  errorMessage: string | null;
  checkoutBytes: number | null;
  findingsCount: number;
  newFindings: number;
  resolvedFindings: number;
  scanners: ScannerExecution[];
}

export interface PlanningNote {
  repositoryId: string | null;
  repository: string;
  note: string;
}

export interface ScanRunDetail {
  run: ScanRun;
  jobs: ScanJob[];
  planningNotes: PlanningNote[];
}

export interface Finding {
  id: string;
  repositoryId: string;
  repositoryName: string;
  branch: string;
  type: 'SECURITY' | 'QUALITY' | 'SECRET' | 'DEPENDENCY';
  severity: Severity;
  scanner: string;
  ruleId: string;
  title: string;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  cwes: string[];
  cve: string | null;
  cvssScore: number | null;
  packageName: string | null;
  packageVersion: string | null;
  fixedVersion: string | null;
  status: 'OPEN' | 'RESOLVED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE';
  firstSeenAt: string;
  lastSeenAt: string;
  commitSha: string | null;
  scanners: string[];
}

export interface FindingPage {
  page: { items: Finding[]; page: number; size: number; totalElements: number; totalPages: number };
  bySeverity: Record<Severity, number>;
}
