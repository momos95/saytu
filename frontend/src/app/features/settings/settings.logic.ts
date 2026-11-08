/** Pure helpers of the settings page. */

export interface CronPreset {
  label: string;
  cron: string;
}

export const CRON_PRESETS: CronPreset[] = [
  { label: 'Chaque nuit à 2 h', cron: '0 2 * * *' },
  { label: 'Du lundi au vendredi à 6 h', cron: '0 6 * * 1-5' },
  { label: 'Chaque lundi à 7 h', cron: '0 7 * * 1' },
  { label: 'Le 1er du mois à 3 h', cron: '0 3 1 * *' },
];

const DAYS: Record<string, string> = { '0': 'dimanche', '1': 'lundi', '2': 'mardi', '3': 'mercredi', '4': 'jeudi',
  '5': 'vendredi', '6': 'samedi', '7': 'dimanche', MON: 'lundi', TUE: 'mardi', WED: 'mercredi', THU: 'jeudi', FRI: 'vendredi',
  SAT: 'samedi', SUN: 'dimanche' };

/** Plain-French reading of common cron expressions (5 or 6 fields); the expression itself otherwise. */
export function describeCron(expression: string): string {
  const parts = expression.trim().split(/\s+/);
  const f = parts.length === 6 ? parts.slice(1) : parts;
  if (f.length !== 5) {
    return expression;
  }
  const [min, hour, dom, month, dow] = f;
  if (!/^\d+$/.test(min) || !/^\d+$/.test(hour) || month !== '*') {
    return expression;
  }
  const at = `à ${hour} h${min === '0' ? '' : ' ' + min.padStart(2, '0')}`;
  if (dom === '*' && dow === '*') {
    return `chaque jour ${at}`;
  }
  if (dom === '*' && /^(1-5|MON-FRI)$/i.test(dow)) {
    return `du lundi au vendredi ${at}`;
  }
  if (dom === '*' && DAYS[dow.toUpperCase()]) {
    return `chaque ${DAYS[dow.toUpperCase()]} ${at}`;
  }
  if (/^\d+$/.test(dom) && dow === '*') {
    return `le ${dom === '1' ? '1er' : dom} de chaque mois ${at}`;
  }
  return expression;
}

/** Random hexadecimal secret for webhook signatures (browser crypto). */
export function randomSecret(bytes = 24): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, b => b.toString(16).padStart(2, '0')).join('');
}

export const ROLE_LABELS: Record<string, string> = {
  VIEWER: 'Lecture (VIEWER)', AUDITOR: 'Audit et triage (AUDITOR)', ADMIN: 'Administration (ADMIN)',
};

export const DELIVERY_LABELS: Record<string, string> = { PENDING: 'en attente', DELIVERED: 'livrée', FAILED: 'abandonnée' };
