/** DTOs of the phase 6 endpoints (InsightService, FindingQueryService, ReportService). */
import { Finding, ScanRun, ScoreView, Severity } from '../audits/audits.model';

export type FindingType = Finding['type'];
export type FindingStatus = Finding['status'];
export type ReportFormat = 'html' | 'pdf' | 'json' | 'sarif';

/** severity → type → number of open findings (every key present). */
export type SeverityTypeCounts = Record<Severity, Record<FindingType, number>>;

export interface TrendPoint {
  day: string;
  security: number | null;
  quality: number | null;
  global: number | null;
  coverage: number;
  reliability: ScoreView['reliability'];
}

export interface FlowPoint {
  week: string;
  opened: number;
  resolved: number;
}

export interface PriorityRepository {
  repositoryId: string;
  repository: string;
  languages: string[];
  critical: number;
  high: number;
  securityFindings: number;
  openFindings: number;
  score: ScoreView | null;
}

export interface Dashboard {
  global: ScoreView | null;
  counters: {
    auditedRepositories: number;
    openFindings: number;
    newLast7Days: number;
    resolvedLast7Days: number;
    triaged: number;
    lastAuditAt: string | null;
  };
  openBySeverity: SeverityTypeCounts;
  trend: TrendPoint[];
  weeklyFlow: FlowPoint[];
  priorities: PriorityRepository[];
  recentRuns: ScanRun[];
}

export interface RepositoryOverview {
  repository: {
    id: string;
    fullName: string;
    name: string;
    webUrl: string | null;
    defaultBranch: string | null;
    visibility: string | null;
    archived: boolean;
    removed: boolean;
    languages: string[];
    languagesUpdatedAt: string | null;
    lastActivityAt: string | null;
    namespaceId: string | null;
    namespace: string | null;
    connectionName: string;
    providerType: string;
  };
  score: ScoreView | null;
  branches: { branch: string; score: ScoreView | null; openBySeverity: Record<Severity, number>; openFindings: number }[];
  openBySeverity: SeverityTypeCounts;
  trend: TrendPoint[];
  weeklyFlow: FlowPoint[];
  topRules: { scanner: string; ruleId: string; title: string; severity: Severity; count: number }[];
  actionPlan: ActionPlan;
  recentJobs: {
    id: string;
    runId: string;
    branch: string;
    status: string;
    commitSha: string | null;
    queuedAt: string;
    startedAt: string | null;
    finishedAt: string | null;
    findings: number;
    newFindings: number;
    resolvedFindings: number;
    errorMessage: string | null;
  }[];
}

export interface FindingDetail {
  finding: Finding;
  description: string;
  evidence: string | null;
  recommendation: string | null;
  references: string[];
  cvssVector: string | null;
  packageEcosystem: string | null;
  resolvedAt: string | null;
  statusReason: string | null;
  statusChangedBy: string | null;
  statusChangedAt: string | null;
  occurrences: { scanner: string; ruleId: string; severity: string; filePath: string | null; startLine: number | null;
                 detectedAt: string; scanJobId: string }[];
  history: { fromStatus: string | null; toStatus: string; reason: string | null; changedBy: string; changedAt: string }[];
  /** deterministic fix suggestion (RuleBasedRemediationProvider), null if not available */
  suggestion: Suggestion | null;
}

export interface Suggestion {
  providerId: string;
  topic: string;
  explanation: string;
  impact: string;
  steps: string[];
  exampleLanguage: string;
  vulnerableExample: string;
  fixedCodeExample: string;
  suggestedTests: string[];
  references: string[];
  /** false: only the generic guidance of the category applies */
  specific: boolean;
}

export type ActionKind = 'DEPENDENCY_UPGRADE' | 'DEPENDENCY_WITHOUT_FIX' | 'SECRET' | 'CONFIGURATION' | 'CODE';

export interface ActionItem {
  kind: ActionKind;
  title: string;
  target: string;
  fixedVersion: string | null;
  severity: Severity;
  findings: number;
  securityBefore: number;
  securityAfter: number;
  gain: number;
  exampleFindingId: string;
  query: Record<string, string>;
}

export interface ActionPlan {
  branch: string | null;
  formulaVersion: string;
  securityScore: number | null;
  items: ActionItem[];
}

/** Filters of the findings list, the reports and the URL (all optional). */
export interface FindingFilters {
  repositoryId?: string;
  branch?: string;
  severity?: string[];
  type?: string[];
  status?: string[];
  scanner?: string;
  q?: string;
}

export interface JobRef {
  id: string;
  repositoryId: string;
  repository: string;
  branch: string;
  status: string;
  commitSha: string | null;
  finishedAt: string | null;
  score: ScoreView | null;
}

export interface Comparison {
  base: JobRef;
  head: JobRef;
  introduced: Finding[];
  fixed: Finding[];
  unverified: Finding[];
  persisting: number;
  introducedTotal: number;
  fixedTotal: number;
  unverifiedTotal: number;
  scanners: { scanner: string; baseStatus: string | null; headStatus: string | null; baseVersion: string | null; headVersion: string | null }[];
}

export interface AiExplanation {
  content: Suggestion;
  providerId: string;
  createdAt: string;
}
