import { languageLabel } from './sources.model';
import { branchProblem, discoveryMessage, filterTree, orderTree, parseBranchList } from './sources.logic';
import { Namespace } from './sources.model';

function ns(id: string, fullPath: string, parentId: string | null = null, kind: Namespace['kind'] = 'GROUP'): Namespace {
  return {
    id, connectionId: 'c', externalId: id, kind, fullPath, name: fullPath.split('/').pop() ?? fullPath, parentId,
    webUrl: null, selected: false, includeAllRepositories: false, addedManually: false, removed: false,
    repositoriesSyncedAt: null, repositoriesSyncStatus: null, repositoriesSyncMessage: null, repositoriesTruncated: false,
    repositoryCount: 0, selectedRepositoryCount: 0,
  };
}

describe('sources.logic', () => {
  it('orders namespaces as a tree, personal namespace first', () => {
    const rows = orderTree([
      ns('3', 'acme/pay/core', '2', 'SUBGROUP'),
      ns('2', 'acme/pay', '1', 'SUBGROUP'),
      ns('9', 'zeta'),
      ns('1', 'acme'),
      ns('u', 'seckma95', null, 'USER'),
      ns('4', 'acme/ops', '1', 'SUBGROUP'),
    ]);
    expect(rows.map(r => `${r.depth}:${r.namespace.fullPath}`)).toEqual([
      '0:seckma95', '0:acme', '1:acme/ops', '1:acme/pay', '2:acme/pay/core', '0:zeta',
    ]);
  });

  it('survives unknown parents and cycles', () => {
    const rows = orderTree([ns('a', 'a', 'b'), ns('b', 'b', 'a'), ns('c', 'c', 'missing')]);
    expect(rows.length).toBe(3);
    expect(rows.find(r => r.namespace.id === 'c')?.depth).toBe(0);
  });

  it('filters while keeping ancestors', () => {
    const rows = orderTree([ns('1', 'acme'), ns('2', 'acme/pay', '1', 'SUBGROUP'), ns('3', 'zeta')]);
    expect(filterTree(rows, 'PAY').map(r => r.namespace.id)).toEqual(['1', '2']);
    expect(filterTree(rows, '  ').length).toBe(3);
  });

  it('parses typed branch lists', () => {
    expect(parseBranchList(' main, develop\nrelease/1.0;main  ')).toEqual(['main', 'develop', 'release/1.0']);
    expect(parseBranchList('')).toEqual([]);
  });

  it('applies the same branch rules as the backend', () => {
    for (const ok of ['main', 'feature/ABC-12_login', 'release/2026.11', 'v1.2.3']) {
      expect(branchProblem(ok)).toBeNull();
    }
    for (const bad of ['', '-x', 'a..b', 'a b', 'a~1', 'x.lock', 'feat/.hidden', 'main/', '/main', 'a//b', 'HEAD',
      'a@{1}', 'main.', 'a\nb', 'a:b', 'a*', 'a[', 'a\\b', 'x'.repeat(256)]) {
      expect(branchProblem(bad)).not.toBeNull();
    }
  });

  it('describes synchronisation outcomes', () => {
    const base = { found: 40, added: 3, removed: 1, truncated: false, retryAfterSeconds: null, message: null };
    expect(discoveryMessage({ ...base, status: 'OK' })).toContain('40 trouvé(s)');
    expect(discoveryMessage({ ...base, status: 'RATE_LIMITED', retryAfterSeconds: 60 })).toContain('dans 60 s');
    expect(discoveryMessage({ ...base, status: 'UNREACHABLE', message: 'Timed out' })).toContain('Timed out');
  });

  it('labels the detected languages', () => {
    expect(languageLabel('cpp')).toBe('C++');
    expect(languageLabel('csharp')).toBe('C#');
    expect(languageLabel('typescript')).toBe('TypeScript');
    expect(languageLabel('unknown-lang')).toBe('unknown-lang');
  });
});
