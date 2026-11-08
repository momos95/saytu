/** DTOs of the phase 7 endpoints (schedules, webhooks, users, local AI). */

export type ScheduleScope = 'ALL_SELECTED' | 'REPOSITORIES' | 'NAMESPACES';

export interface Schedule {
  id: string;
  name: string;
  cronExpression: string;
  timeZone: string;
  scope: ScheduleScope;
  enabled: boolean;
  nextFireAt: string | null;
  lastFiredAt: string | null;
  lastRunId: string | null;
  lastRunStatus: string | null;
  lastOutcome: string | null;
  repositoryIds: string[];
  namespaceIds: string[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScheduleRequest {
  name: string;
  cronExpression: string;
  timeZone: string;
  scope: ScheduleScope;
  enabled: boolean;
  repositoryIds: string[];
  namespaceIds: string[];
}

export interface Webhook {
  id: string;
  name: string;
  /** masked: scheme, host and port only */
  url: string;
  format: 'GENERIC' | 'SLACK';
  minSeverity: string;
  events: string[];
  enabled: boolean;
  hasSecret: boolean;
  lastStatus: string | null;
  lastDeliveredAt: string | null;
  createdBy: string;
  createdAt: string;
}

export interface WebhookRequest {
  name: string;
  url: string;
  format: 'GENERIC' | 'SLACK';
  minSeverity: string;
  events: string[];
  enabled: boolean;
  /** null = keep, '' = remove */
  secret: string | null;
}

export interface Delivery {
  id: string;
  event: string;
  status: 'PENDING' | 'DELIVERED' | 'FAILED';
  attempts: number;
  httpStatus: number | null;
  error: string | null;
  createdAt: string;
  deliveredAt: string | null;
  nextAttemptAt: string;
}

export interface TestResult {
  delivered: boolean;
  httpStatus: number | null;
  message: string;
}

export interface UserStatus {
  configured: boolean;
  message: string;
}

export interface AppUser {
  id: string;
  username: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  enabled: boolean;
  role: 'VIEWER' | 'AUDITOR' | 'ADMIN' | null;
  createdAt: string | null;
  requiredActions: string[];
  self: boolean;
}

export interface Credentials {
  user: AppUser;
  temporaryPassword: string;
}

export interface AiSettings {
  enabled: boolean;
  baseUrl: string;
  model: string;
  timeoutSeconds: number;
}

export interface AiTest {
  reachable: boolean;
  modelAvailable: boolean;
  models: string[];
  message: string;
}
