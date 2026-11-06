import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';
import { PlannedPage } from './features/planned/planned-page';
import { Shell } from './layout/shell';
import { NAV_ITEMS } from './navigation';

export const routes: Routes = [
  {
    path: 'login',
    title: 'Connexion · SAYTU',
    loadComponent: () => import('./features/login/login-page').then(m => m.LoginPage),
  },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'connections',
        title: 'Connexions Git · SAYTU',
        loadComponent: () => import('./features/connections/connections-page').then(m => m.ConnectionsPage),
      },
      {
        path: 'repositories',
        title: 'Organisations et dépôts · SAYTU',
        loadComponent: () => import('./features/repositories/repositories-page').then(m => m.RepositoriesPage),
      },
      {
        path: 'scan-settings',
        title: 'Scanners et branches · SAYTU',
        loadComponent: () => import('./features/scan-settings/scan-settings-page').then(m => m.ScanSettingsPage),
      },
      {
        path: 'dashboard',
        title: 'Tableau de bord · SAYTU',
        loadComponent: () => import('./features/dashboard/dashboard-page').then(m => m.DashboardPage),
      },
      {
        path: 'repositories/:id',
        title: 'Dépôt · SAYTU',
        loadComponent: () => import('./features/repository-detail/repository-detail-page').then(m => m.RepositoryDetailPage),
      },
      {
        path: 'findings',
        title: 'Vulnérabilités · SAYTU',
        loadComponent: () => import('./features/findings/findings-page').then(m => m.FindingsPage),
      },
      {
        path: 'findings/:id',
        title: 'Vulnérabilité · SAYTU',
        loadComponent: () => import('./features/findings/finding-detail-page').then(m => m.FindingDetailPage),
      },
      {
        path: 'audits',
        title: 'Audits · SAYTU',
        loadComponent: () => import('./features/audits/audits-page').then(m => m.AuditsPage),
      },
      ...NAV_ITEMS.filter(item => item.data).map(item => ({
        path: item.path,
        component: PlannedPage,
        data: item.data,
        title: `${item.data!.title} · SAYTU`,
      })),
    ],
  },
  { path: '**', redirectTo: 'dashboard' },
];
