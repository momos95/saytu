/** Pure helpers of the discovery pages (no Angular import: unit-tested in plain Node). */
import { Namespace } from './sources.model';

export interface TreeRow {
  namespace: Namespace;
  depth: number;
}

/**
 * Orders namespaces as a tree (parents before their children, siblings by path) and computes the
 * indentation depth. Namespaces whose parent is unknown are shown as roots; cycles cannot loop.
 */
export function orderTree(namespaces: Namespace[]): TreeRow[] {
  const byId = new Map(namespaces.map(n => [n.id, n]));
  const children = new Map<string | null, Namespace[]>();
  for (const n of namespaces) {
    const parent = n.parentId && byId.has(n.parentId) ? n.parentId : null;
    const list = children.get(parent) ?? [];
    list.push(n);
    children.set(parent, list);
  }
  const rank = (n: Namespace) => (n.kind === 'USER' || n.kind === 'LOCAL_DIRECTORY' ? 0 : 1);
  for (const list of children.values()) {
    list.sort((a, b) => rank(a) - rank(b) || a.fullPath.localeCompare(b.fullPath));
  }
  const rows: TreeRow[] = [];
  const visited = new Set<string>();
  const walk = (parent: string | null, depth: number) => {
    for (const n of children.get(parent) ?? []) {
      if (visited.has(n.id)) {
        continue;
      }
      visited.add(n.id);
      rows.push({ namespace: n, depth });
      walk(n.id, depth + 1);
    }
  };
  walk(null, 0);
  // members of a parent cycle are never reached from a root: append them as roots
  for (const n of namespaces) {
    if (!visited.has(n.id)) {
      visited.add(n.id);
      rows.push({ namespace: n, depth: 0 });
    }
  }
  return rows;
}

/** Keeps rows whose path or name contains the text, plus their ancestors so the tree stays readable. */
export function filterTree(rows: TreeRow[], text: string): TreeRow[] {
  const q = text.trim().toLowerCase();
  if (!q) {
    return rows;
  }
  const byId = new Map(rows.map(r => [r.namespace.id, r.namespace]));
  const keep = new Set<string>();
  for (const r of rows) {
    if (r.namespace.fullPath.toLowerCase().includes(q) || r.namespace.name.toLowerCase().includes(q)) {
      let current: Namespace | undefined = r.namespace;
      while (current && !keep.has(current.id)) {
        keep.add(current.id);
        current = current.parentId ? byId.get(current.parentId) : undefined;
      }
    }
  }
  return rows.filter(r => keep.has(r.namespace.id));
}

/** Splits a typed list ("main, develop\nrelease/1.0") into unique names, order preserved. */
export function parseBranchList(text: string): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const part of text.split(/[\s,;]+/)) {
    const name = part.trim();
    if (name && !seen.has(name)) {
      seen.add(name);
      result.push(name);
    }
  }
  return result;
}

/** Same rules as the backend (git check-ref-format); returns a French reason or null when valid. */
export function branchProblem(name: string): string | null {
  if (!name) {
    return 'nom vide';
  }
  if (name.length > 255) {
    return 'plus de 255 caractères';
  }
  if (name.startsWith('-')) {
    return 'ne doit pas commencer par « - »';
  }
  if (name === '@' || name === 'HEAD') {
    return 'nom réservé';
  }
  if (name.includes('..') || name.includes('@{') || name.includes('//')) {
    return 'ne doit pas contenir « .. », « @{ » ni « // »';
  }
  if (name.startsWith('/') || name.endsWith('/') || name.endsWith('.')) {
    return 'ne doit pas commencer par « / » ni finir par « / » ou « . »';
  }
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x20\x7f~^:?*[\\]/.test(name)) {
    return 'caractère interdit (espace, ~ ^ : ? * [ \\ ou caractère de contrôle)';
  }
  for (const component of name.split('/')) {
    if (component.startsWith('.')) {
      return 'un segment ne doit pas commencer par « . »';
    }
    if (component.endsWith('.lock')) {
      return 'un segment ne doit pas finir par « .lock »';
    }
  }
  return null;
}

/** Human-readable French outcome of a synchronisation. */
export function discoveryMessage(r: { status: string; found: number; added: number; removed: number;
  truncated: boolean; retryAfterSeconds: number | null; message: string | null }): string {
  const counts = `${r.found} trouvé(s), ${r.added} nouveau(x), ${r.removed} retiré(s)`;
  switch (r.status) {
    case 'OK':
      return `Synchronisation terminée : ${counts}.`;
    case 'PARTIAL':
      return `Synchronisation partielle (limite atteinte) : ${counts}.`;
    case 'RATE_LIMITED':
      return `Limite de requêtes de la plateforme atteinte : ${counts} conservés.`
        + (r.retryAfterSeconds ? ` Réessayez dans ${r.retryAfterSeconds} s.` : '');
    default:
      return `Synchronisation interrompue (${r.status}) : ${counts} conservés. ${r.message ?? ''}`.trim();
  }
}
