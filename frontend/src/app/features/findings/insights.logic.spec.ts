import { ageInDays, gainLabel, fileNameFrom, filtersFromParams, filtersToHttpPairs, filtersToParams, flowBars, severityTotals, shares, toggle, trendSeries } from './insights.logic';
import { SeverityTypeCounts, TrendPoint } from './insights.model';

describe('insights logic', () => {
  it('reads filters from the URL, dropping unknown values', () => {
    const f = filtersFromParams({ severity: 'high,critical,bogus,HIGH', status: ['OPEN'], type: 'secret', q: '  sql  ', branch: '' });
    expect(f).toEqual({ severity: ['HIGH', 'CRITICAL'], status: ['OPEN'], type: ['SECRET'], q: 'sql' });
    expect(filtersToParams(f)).toEqual({ severity: 'HIGH,CRITICAL', type: 'SECRET', status: 'OPEN', q: 'sql' });
    expect(filtersToHttpPairs({ repositoryId: 'r1', severity: ['HIGH', 'LOW'] }))
      .toEqual([['repositoryId', 'r1'], ['severity', 'HIGH'], ['severity', 'LOW']]);
    expect(filtersFromParams({ q: 'x'.repeat(300) }).q!.length).toBe(200);
  });

  it('toggles a value and empties to undefined', () => {
    expect(toggle(undefined, 'HIGH')).toEqual(['HIGH']);
    expect(toggle(['HIGH', 'LOW'], 'HIGH')).toEqual(['LOW']);
    expect(toggle(['HIGH'], 'HIGH')).toBeUndefined();
  });

  it('totals open findings per severity', () => {
    const counts = {
      CRITICAL: { SECURITY: 1, SECRET: 0, DEPENDENCY: 2, QUALITY: 0 },
      HIGH: { SECURITY: 0, SECRET: 3, DEPENDENCY: 0, QUALITY: 4 },
      MEDIUM: { SECURITY: 0, SECRET: 0, DEPENDENCY: 0, QUALITY: 0 },
      LOW: { SECURITY: 0, SECRET: 0, DEPENDENCY: 0, QUALITY: 5 },
      INFO: { SECURITY: 0, SECRET: 0, DEPENDENCY: 0, QUALITY: 0 },
    } as SeverityTypeCounts;
    expect(severityTotals(counts)).toEqual({ bySeverity: { CRITICAL: 3, HIGH: 7, MEDIUM: 0, LOW: 5, INFO: 0 }, total: 15 });
    expect(severityTotals(null).total).toBe(0);
    expect(shares([0, 1, 999])).toEqual([0, 1, 99.9]);
    expect(shares([0, 0])).toEqual([0, 0]);
  });

  it('breaks the score line where the score is missing instead of drawing 0', () => {
    const p = (global: number | null): TrendPoint =>
      ({ day: '2026-11-01T00:00:00Z', global, security: global, quality: 50, coverage: 100, reliability: 'HIGH' });
    const series = trendSeries([p(100), p(null), p(0), p(50)], 300, 100);
    const global = series.find(s => s.key === 'global')!;
    expect(global.segments).toEqual(['0,0', '200,100 300,50']);
    expect(series.find(s => s.key === 'quality')!.segments).toEqual(['0,50 100,50 200,50 300,50']);
    expect(trendSeries([p(80)], 300, 100)[0].segments).toEqual(['150,20']);
  });

  it('scales weekly bars on the largest value', () => {
    const bars = flowBars([{ week: 'w1', opened: 4, resolved: 2 }, { week: 'w2', opened: 0, resolved: 8 }], 80);
    expect(bars.map(b => [b.openedH, b.resolvedH])).toEqual([[40, 20], [0, 80]]);
    expect(flowBars([{ week: 'w', opened: 0, resolved: 0 }], 80)[0].openedH).toBe(0);
  });

  it('takes a safe file name from Content-Disposition', () => {
    expect(fileNameFrom(`attachment; filename="r.pdf"; filename*=UTF-8''d%C3%A9p%C3%B4t.pdf`, 'x')).toBe('dépôt.pdf');
    expect(fileNameFrom('attachment; filename="saytu-global.sarif"', 'x')).toBe('saytu-global.sarif');
    expect(fileNameFrom('attachment; filename="../../etc/passwd"', 'x')).toBe('_.._etc_passwd');
    expect(fileNameFrom(null, 'fallback.json')).toBe('fallback.json');
  });

  it('computes ages in days', () => {
    expect(ageInDays('2026-11-01T00:00:00Z', Date.parse('2026-11-06T12:00:00Z'))).toBe(5);
    expect(ageInDays(null)).toBeNull();
  });

  it('labels the security gain of an action', () => {
    expect(gainLabel(12.46)).toBe('+12,5');
    expect(gainLabel(0.01)).toBe('');
    expect(gainLabel(3)).toBe('+3');
  });
});
