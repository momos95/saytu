import { ChangeDetectionStrategy, Component, signal } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { NAV_ITEMS } from '../app.routes';

/** Application frame: header, collapsible side navigation (mobile) and routed content. */
@Component({
  selector: 'acs-shell',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="topbar">
      <button type="button" class="menu-toggle" (click)="menuOpen.set(!menuOpen())"
              [attr.aria-expanded]="menuOpen()" aria-controls="acs-nav" aria-label="Menu">☰</button>
      <a routerLink="/dashboard" class="brand"><span class="logo" aria-hidden="true">◆</span> AfriCodeShield</a>
      <span class="env">On-premise</span>
    </header>
    <div class="layout">
      <nav id="acs-nav" [class.open]="menuOpen()" aria-label="Navigation principale">
        <ul>
          @for (item of navItems; track item.path) {
            <li>
              <a [routerLink]="'/' + item.path" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }"
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
  readonly navItems = NAV_ITEMS;
  readonly menuOpen = signal(false);
}
