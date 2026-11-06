import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { NAV_ITEMS } from '../navigation';
import { AuthService } from '../core/auth/auth.service';

/** Application frame for signed-in users: header, collapsible side navigation, routed content. */
@Component({
  selector: 'saytu-shell',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="topbar">
      <button type="button" class="menu-toggle" (click)="menuOpen.set(!menuOpen())"
              [attr.aria-expanded]="menuOpen()" aria-controls="saytu-nav" aria-label="Menu">☰</button>
      <a routerLink="/dashboard" class="brand"><span class="logo" aria-hidden="true">◆</span> SAYTU</a>
      <div class="user">
        <span class="name" data-testid="user-name">{{ auth.displayName() }}</span>
        @for (role of auth.roles(); track role) {
          <span class="role">{{ role }}</span>
        }
        <button type="button" class="logout" (click)="auth.logout()">Déconnexion</button>
      </div>
    </header>
    <div class="layout">
      <nav id="saytu-nav" [class.open]="menuOpen()" aria-label="Navigation principale">
        <ul>
          @for (item of navItems; track item.path) {
            <li>
              <a [routerLink]="'/' + item.path" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: false }"
                 (click)="menuOpen.set(false)">
                <span class="icon" aria-hidden="true">{{ item.icon }}</span>{{ item.label }}
              </a>
            </li>
          }
        </ul>
      </nav>
      <main>
        <router-outlet />
      </main>
    </div>
  `,
  styleUrl: './shell.scss',
})
export class Shell {
  readonly auth = inject(AuthService);
  readonly navItems = NAV_ITEMS;
  readonly menuOpen = signal(false);
}
