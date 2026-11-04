import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';
import { PlannedPage } from './features/planned/planned-page';
import { Shell } from './layout/shell';
import { NAV_ITEMS } from './navigation';

export const routes: Routes = [
  {
    path: 'login',
    title: 'Connexion · AfriCodeShield',
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
        title: 'Connexions Git · AfriCodeShield',
        loadComponent: () => import('./features/connections/connections-page').then(m => m.ConnectionsPage),
      },
      ...NAV_ITEMS.filter(item => item.data).map(item => ({
        path: item.path,
        component: PlannedPage,
        data: item.data,
        title: `${item.data!.title} · AfriCodeShield`,
      })),
    ],
  },
  { path: '**', redirectTo: 'dashboard' },
];
