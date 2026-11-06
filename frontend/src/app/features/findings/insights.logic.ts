import { Severity } from '../audits/audits.model';
import { FindingFilters, FlowPoint, SeverityTypeCounts, TrendPoint } from './insights.model';

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const TYPES = ['SECURITY', 'SECRET', 'DEPENDENCY', 'QUALITY'] as const;
export const STATUSES = ['OPEN', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'RESOLVED'] as const;

export const TYPE_LABELS: Record<string, string> = {
  SECURITY: 'Sécurité', SECRET: 'Secret', DEPENDENCY: 'Dépendance', QUALITY: 'Qualité',
};
export const STATUS_LABELS: Record<string, string> = {
  OPEN: 'Ouverte', ACCEPTED_RISK: 'Risque accepté', FALSE_POSITIVE: 'Faux positif', RESOLVED: 'Corrigée',
};

const LIST_KEYS = ['severity', 'type', 'status'] as const;
const TEXT_KEYS = ['repositoryId', 'branch', 'scanner', 'q'] as const;

/** URL query params → filters (unknown values dropped, lists de-duplicated). */
export function filtersFromParams(params: Record<string, string | string[] | undefined>): FindingFilters {
  const allowed: Record<(typeof LIST_KEYS)[number], readonly string[]> = { severity: SEVERITIES, type: TYPES, status: STATUSES };
  const f: FindingFilters = {};
  for (const k of LIST_KEYS) {
    const raw = params[k];
    const values = (Array.isArray(raw) ? raw : raw ? raw.split(',') : []).map(v => v.trim().toUpperCase());
    const kept = [...new Set(values.filter(v => allowed[k].includes(v)))];
    if (kept.length) {
      f[k] = kept;
    }
  }
  for (const k of TEXT_KEYS) {
    const raw = params[k];
    const v = (Array.isArray(raw) ? raw[0] : raw)?.trim();
    if (v) {
      f[k] = v.slice(0, 200);
    }
  }
  return f;
}

/** Filters → flat query params (lists comma-joined), empty values omitted: used for the URL. */
export function filtersToParams(f: FindingFilters): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of LIST_KEYS) {
    if (f[k]?.length) {
      out[k] = f[k]!.join(',');
    }
  }
  for (const k of TEXT_KEYS) {
    if (f[k]) {
      out[k] = f[k]!;
    }
  }
  return out;
}

/** Filters → repeated HTTP params ([name, value] pairs) for the API. */
export function filtersToHttpPairs(f: FindingFilters): [string, string][] {
  const pairs: [string, string][] = [];
  for (const k of TEXT_KEYS) {
    if (f[k]) {
      pairs.push([k, f[k]!]);
    }
  }
  for (const k of LIST_KEYS) {
    for (const v of f[k] ?? []) {
      pairs.push([k, v]);
    }
  }
  return pairs;
}

export function toggle(list: string[] | undefined, value: string): string[] | undefined {
  const next = (list ?? []).includes(value) ? list!.filter(v => v !== value) : [...(list ?? []), value];
  return next.length ? next : undefined;
}

/** Total per severity (all types) and grand total. */
export function severityTotals(counts: SeverityTypeCounts | null | undefined): { bySeverity: Record<Severity, number>; total: number } {
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<Severity, number>;
  let total = 0;
  if (counts) {
    for (const s of SEVERITIES) {
      const n = Object.values(counts[s] ?? {}).reduce((a, b) => a + b, 0);
      bySeverity[s] = n;
      total += n;
    }
  }
  return { bySeverity, total };
}

/** Width (0..100 %) of each segment of a stacked bar; a non-zero value is at least 1 % so it stays visible. */
export function shares(values: number[]): number[] {
  const total = values.reduce((a, b) => a + b, 0);
  return values.map(v => (total === 0 || v === 0 ? 0 : Math.max(1, (v / total) * 100)));
}

export interface ChartSeries {
  key: 'global' | 'security' | 'quality';
  label: string;
  /** SVG polyline points; segments are split where the score is missing */
  segments: string[];
}

/**
 * Score trend as SVG polylines on a width × height box (y: 0..100, x: one slot per point).
 * A day without a score breaks the line rather than being drawn as 0 or 100.
 */
export function trendSeries(points: TrendPoint[], width: number, height: number): ChartSeries[] {
  const defs: { key: ChartSeries['key']; label: string }[] = [
    { key: 'global', label: 'Global' }, { key: 'security', label: 'Sécurité' }, { key: 'quality', label: 'Qualité' }];
  const step = points.length > 1 ? width / (points.length - 1) : 0;
  return defs.map(({ key, label }) => {
    const segments: string[] = [];
    let current: string[] = [];
    points.forEach((p, i) => {
      const v = p[key];
      if (v === null || v === undefined) {
        if (current.length) {
          segments.push(current.join(' '));
        }
        current = [];
        return;
      }
      const x = points.length === 1 ? width / 2 : i * step;
      const y = height - (Math.min(100, Math.max(0, v)) / 100) * height;
      current.push(`${round(x)},${round(y)}`);
    });
    if (current.length) {
      segments.push(current.join(' '));
    }
    return { key, label, segments };
  });
}

/** Bar heights (px) of the weekly opened / resolved counts, scaled on the largest value. */
export function flowBars(flow: FlowPoint[], height: number): { week: string; opened: number; resolved: number; openedH: number; resolvedH: number }[] {
  const max = Math.max(1, ...flow.map(f => Math.max(f.opened, f.resolved)));
  return flow.map(f => ({ ...f, openedH: round((f.opened / max) * height), resolvedH: round((f.resolved / max) * height) }));
}

/** File name from a Content-Disposition header (RFC 6266 filename* preferred), or a fallback. */
export function fileNameFrom(disposition: string | null, fallback: string): string {
  if (disposition) {
    const star = /filename\*=UTF-8''([^;]+)/i.exec(disposition);
    if (star) {
      try {
        return sanitizeFileName(decodeURIComponent(star[1].trim()), fallback);
      } catch {
        /* fall through */
      }
    }
    const plain = /filename="([^"]+)"/i.exec(disposition) ?? /filename=([^;]+)/i.exec(disposition);
    if (plain) {
      return sanitizeFileName(plain[1].trim(), fallback);
    }
  }
  return fallback;
}

function sanitizeFileName(name: string, fallback: string): string {
  const clean = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').replace(/^\.+/, '');
  return clean || fallback;
}

/** Days between now and an ISO date, for "il y a 3 j" style labels. */
export function ageInDays(iso: string | null, now = Date.now()): number | null {
  if (!iso) {
    return null;
  }
  return Math.max(0, Math.floor((now - Date.parse(iso)) / 86_400_000));
}

function round(n: number): number {
  return Math.round(n * 10) / 10;
}

export const ACTION_LABELS: Record<string, string> = {
  DEPENDENCY_UPGRADE: 'Mise à jour', DEPENDENCY_WITHOUT_FIX: 'Dépendance sans correctif', SECRET: 'Secret',
  CONFIGURATION: 'Configuration', CODE: 'Code',
};

/** "+12,5" style gain label; nothing for a negligible gain. */
export function gainLabel(gain: number): string {
  if (gain < 0.05) {
    return '';
  }
  const rounded = Math.round(gain * 10) / 10;
  return `+${rounded.toLocaleString('fr-FR')}`;
}
