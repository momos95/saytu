import { PlannedPageData } from './features/planned/planned-page';

/** Navigation entry shown in the side menu. */
export interface NavItem {
  path: string;
  label: string;
  icon: string;
  /** Placeholder data while the page is not delivered; absent once the real page exists. */
  data?: PlannedPageData;
}

/**
 * Side menu. The detail pages (a repository, a vulnerability) are reached from the lists, not from the
 * menu. Pages not delivered yet are routed placeholders that state which phase delivers them.
 */
export const NAV_ITEMS: NavItem[] = [
  { path: 'dashboard', label: 'Tableau de bord', icon: '◧' },
  { path: 'connections', label: 'Connexions Git', icon: '⇄' },
  { path: 'repositories', label: 'Organisations & dépôts', icon: '▤' },
  { path: 'scan-settings', label: 'Scanners & branches', icon: '⚙' },
  { path: 'audits', label: 'Audits', icon: '▶' },
  { path: 'findings', label: 'Vulnérabilités', icon: '⚑' },
  { path: 'settings', label: 'Utilisateurs & paramètres', icon: '☰',
    data: { title: 'Utilisateurs et paramètres', phase: 7, summary: 'Rôles ADMIN / AUDITOR / VIEWER, planification, webhooks et paramètres de scoring.' } },
];
