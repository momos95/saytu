import { Routes } from '@angular/router';
import { PlannedPage, PlannedPageData } from './features/planned/planned-page';

/** Navigation entry shown in the side menu. */
export interface NavItem {
  path: string;
  label: string;
  icon: string;
  data: PlannedPageData;
}

/**
 * The ten pages of the specification. In phase 1 they are routed placeholders that state which
 * phase delivers them; each one is replaced by its real feature component in later phases.
 */
export const NAV_ITEMS: NavItem[] = [
  { path: 'dashboard', label: 'Tableau de bord', icon: '◧',
    data: { title: 'Tableau de bord', phase: 6, summary: 'Scores sécurité / qualité / global, répartition par criticité, tendances et dépôts prioritaires.' } },
  { path: 'connections', label: 'Connexions Git', icon: '⇄',
    data: { title: 'Connexions Git', phase: 2, summary: 'GitLab, GitHub, Bitbucket et dépôts locaux : ajout, test de connexion, chiffrement des tokens.' } },
  { path: 'repositories', label: 'Organisations & dépôts', icon: '▤',
    data: { title: 'Organisations et dépôts', phase: 3, summary: 'Découverte paginée des organisations, groupes, workspaces et sélection des dépôts.' } },
  { path: 'scan-settings', label: 'Scanners & branches', icon: '⚙',
    data: { title: 'Configuration des scanners et branches', phase: 3, summary: 'Activation des scanners, limites, branches main / master / develop ou liste libre.' } },
  { path: 'audits', label: 'Audits', icon: '▶',
    data: { title: 'Historique et exécution des audits', phase: 4, summary: 'Lancement manuel, file d’exécution, statut par scanner, comparaison de deux scans.' } },
  { path: 'repositories/detail', label: 'Détail dépôt', icon: '◫',
    data: { title: 'Détail d’un dépôt', phase: 6, summary: 'Scores par branche, couverture, historique et vulnérabilités du dépôt.' } },
  { path: 'findings', label: 'Vulnérabilités', icon: '⚑',
    data: { title: 'Vulnérabilités', phase: 5, summary: 'Liste filtrable par sévérité, type, scanner, statut, dépôt et branche.' } },
  { path: 'findings/detail', label: 'Détail vulnérabilité', icon: '◉',
    data: { title: 'Détail d’une vulnérabilité', phase: 7, summary: 'Preuve expurgée, CWE / CVE / CVSS, recommandations déterministes et IA locale optionnelle.' } },
  { path: 'settings', label: 'Utilisateurs & paramètres', icon: '☰',
    data: { title: 'Utilisateurs et paramètres', phase: 7, summary: 'Rôles ADMIN / AUDITOR / VIEWER, planification, webhooks et paramètres de scoring.' } },
];

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
  ...NAV_ITEMS.map(item => ({ path: item.path, component: PlannedPage, data: item.data, title: `${item.data.title} · AfriCodeShield` })),
  { path: '**', redirectTo: 'dashboard' },
];
