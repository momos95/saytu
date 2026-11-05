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
