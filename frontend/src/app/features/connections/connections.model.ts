/** Mirrors the backend DTOs of /api/v1/git-connections. */

export type ProviderType = 'GITLAB' | 'GITHUB' | 'BITBUCKET_CLOUD' | 'BITBUCKET_DATA_CENTER' | 'LOCAL';

export interface LastTest {
  status: string;
  message: string | null;
  authenticatedAs: string | null;
  serverVersion: string | null;
  warnings: string[];
  testedAt: string;
}

export interface GitConnection {
  id: string;
  name: string;
  providerType: ProviderType;
  baseUrl: string;
  apiUrl: string | null;
  username: string | null;
  hasToken: boolean;
  enabled: boolean;
  lastTest: LastTest | null;
  tokenExpiresAt: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface GitConnectionRequest {
  name: string;
  providerType: ProviderType;
  baseUrl: string | null;
  apiUrl: string | null;
  username: string | null;
  /** write-only; null keeps the stored token on update */
  token: string | null;
  clearToken: boolean;
  enabled: boolean;
  version: number | null;
}

export interface ConnectionTest {
  success: boolean;
  status: string;
  message: string | null;
  authenticatedAs: string | null;
  serverVersion: string | null;
  grantedScopes: string[];
  warnings: string[];
  tokenExpiresAt: string | null;
  testedAt: string;
}

export interface ProviderInfo {
  type: ProviderType;
  label: string;
  urlPlaceholder: string;
  /** URL may be left empty (SaaS default) */
  urlOptional: boolean;
  usesToken: boolean;
  usernameLabel: string | null;
  help: string;
}

export const PROVIDERS: ProviderInfo[] = [
  {
    type: 'GITLAB',
    label: 'GitLab (gitlab.com ou Self-Managed)',
    urlPlaceholder: 'https://gitlab.example.org — vide pour gitlab.com',
    urlOptional: true,
    usesToken: true,
    usernameLabel: null,
    help: 'Token d’accès personnel, de groupe ou de projet avec les scopes read_api et read_repository (lecture seule suffit).',
  },
  {
    type: 'GITHUB',
    label: 'GitHub (github.com ou Enterprise Server)',
    urlPlaceholder: 'https://github.example.org — vide pour github.com',
    urlOptional: true,
    usesToken: true,
    usernameLabel: null,
    help: 'Token fine-grained avec Contents : read et Metadata : read, ou token classique avec repo et read:org.',
  },
  {
    type: 'BITBUCKET_CLOUD',
    label: 'Bitbucket Cloud',
    urlPlaceholder: 'https://bitbucket.org',
    urlOptional: true,
    usesToken: true,
    usernameLabel: 'E-mail du compte Atlassian (API token)',
    help: 'API token avec read:user, read:workspace et read:repository, et votre e-mail Atlassian ; ou access token de '
      + 'workspace, projet ou dépôt sans e-mail. Les mots de passe d’application ne fonctionnent plus depuis juin 2026.',
  },
  {
    type: 'BITBUCKET_DATA_CENTER',
    label: 'Bitbucket Data Center',
    urlPlaceholder: 'https://bitbucket.example.org',
    urlOptional: false,
    usesToken: true,
    usernameLabel: 'Identifiant (facultatif)',
    help: 'HTTP access token avec la permission lecture sur les projets et dépôts à auditer.',
  },
  {
    type: 'LOCAL',
    label: 'Dépôts locaux',
    urlPlaceholder: '/srv/git/equipe',
    urlOptional: false,
    usesToken: false,
    usernameLabel: null,
    help: 'Répertoire situé sous /srv/git, monté en lecture seule (SAYTU_LOCAL_REPOS_HOST_DIR).',
  },
];

export function providerInfo(type: ProviderType): ProviderInfo {
  return PROVIDERS.find(p => p.type === type) ?? PROVIDERS[0];
}

/** French labels of the backend test statuses. */
export const STATUS_LABELS: Record<string, string> = {
  OK: 'Connexion réussie',
  AUTHENTICATION_FAILED: 'Authentification refusée',
  INSUFFICIENT_PERMISSIONS: 'Permissions insuffisantes',
  RATE_LIMITED: 'Limite de requêtes atteinte',
  NOT_FOUND: 'Introuvable',
  UNREACHABLE: 'Serveur injoignable',
  TLS_ERROR: 'Certificat TLS non reconnu',
  SERVER_ERROR: 'Erreur du serveur distant',
  UNEXPECTED_RESPONSE: 'Réponse inattendue',
  BLOCKED_BY_POLICY: 'Destination interdite',
};

export function statusLabel(status: string | null | undefined): string {
  return status ? (STATUS_LABELS[status] ?? status) : 'Jamais testée';
}
