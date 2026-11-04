/** Mirrors the backend DTOs of discovery, selection and scanner configuration. Framework-free. */

export type NamespaceKind = 'ORGANIZATION' | 'GROUP' | 'SUBGROUP' | 'WORKSPACE' | 'PROJECT' | 'USER' | 'LOCAL_DIRECTORY';
export type BranchMode = 'DEFAULT' | 'PRESET' | 'CUSTOM';

export interface Namespace {
  id: string;
  connectionId: string;
  externalId: string;
  kind: NamespaceKind;
  fullPath: string;
  name: string;
  parentId: string | null;
  webUrl: string | null;
  selected: boolean;
  includeAllRepositories: boolean;
  addedManually: boolean;
  removed: boolean;
  repositoriesSyncedAt: string | null;
  repositoriesSyncStatus: string | null;
  repositoriesSyncMessage: string | null;
  repositoriesTruncated: boolean;
  repositoryCount: number;
  selectedRepositoryCount: number;
}

export interface Repository {
  id: string;
  connectionId: string;
  connectionName: string;
  namespaceId: string | null;
  namespacePath: string | null;
  fullName: string;
  name: string;
  webUrl: string | null;
  defaultBranch: string | null;
  visibility: 'PUBLIC' | 'INTERNAL' | 'PRIVATE' | null;
  archived: boolean;
  removed: boolean;
  selected: boolean;
  scanTarget: boolean;
  branchMode: BranchMode;
  branches: string[];
  lastActivityAt: string | null;
}

export interface PageView<T> {
  items: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

export interface DiscoveryResult {
  status: string;
  message: string | null;
  found: number;
  added: number;
  removed: number;
  truncated: boolean;
  retryAfterSeconds: number | null;
}

export interface RemoteBranch {
  name: string;
  headCommitSha: string;
  isDefault: boolean;
  isProtected: boolean;
  configured: boolean;
}

export interface RemoteBranches {
  branches: RemoteBranch[];
  truncated: boolean;
  status: string;
  message: string | null;
}

export interface ScanTargetSummary {
  selectedNamespaces: number;
  repositories: number;
  defaultBranchMode: number;
  presetBranchMode: number;
  customBranchMode: number;
}

export interface Scanner {
  id: string;
  enabled: boolean;
  timeoutSeconds: number;
  cpuSeconds: number;
  memoryMb: number;
  optional: boolean;
  producedTypes: string[];
  updatedBy: string | null;
  updatedAt: string;
}

export const KIND_LABELS: Record<NamespaceKind, string> = {
  ORGANIZATION: 'Organisation',
  GROUP: 'Groupe',
  SUBGROUP: 'Sous-groupe',
  WORKSPACE: 'Workspace',
  PROJECT: 'Projet',
  USER: 'Compte personnel',
  LOCAL_DIRECTORY: 'Répertoire',
};

export const BRANCH_MODE_LABELS: Record<BranchMode, string> = {
  DEFAULT: 'Branche par défaut',
  PRESET: 'main, master, develop (si présentes)',
  CUSTOM: 'Liste personnalisée',
};

export const SCANNER_LABELS: Record<string, string> = {
  opengrep: 'Opengrep — failles dans le code (SAST)',
  trivy: 'Trivy — dépendances vulnérables et configuration',
  gitleaks: 'Gitleaks — secrets dans le code',
  pmd: 'PMD — qualité du code Java',
  checkstyle: 'Checkstyle — conventions Java',
  'dependency-check': 'OWASP Dependency-Check — dépendances (optionnel, lent)',
};
