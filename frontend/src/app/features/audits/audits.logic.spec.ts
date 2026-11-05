import {
  describeExecution, elapsed, executionTone, formatBytes, formatDuration, formatScore, isActive, location, progress, scopeLabel,
  scoreTitle, scoreTone, translateReason,
} from './audits.logic';
import { ScanRun, ScannerExecution, ScoreView } from './audits.model';

function run(over: Partial<ScanRun>): ScanRun {
  return { id: 'r', triggerType: 'MANUAL', requestedBy: 'awa', status: 'RUNNING', totalJobs: 4, finishedJobs: 1,
    problemJobs: 0, newFindings: 0, createdAt: '2026-11-05T10:00:00Z', startedAt: null, finishedAt: null, planned: true,
    cancelRequested: false, errorMessage: null, scope: 'ALL_TARGETS', ...over };
}

function exec(over: Partial<ScannerExecution>): ScannerExecution {
  return { scanner: 'trivy', status: 'SUCCEEDED', toolVersion: '0.76.1', rulesetVersion: null, durationMs: 1200,
    findingsCount: 3, errorMessage: null, ...over };
}

describe('audits logic', () => {
  it('reports progress and activity', () => {
    expect(progress(run({}))).toBe('1 / 4 branche(s)');
    expect(progress(run({ planned: false, status: 'QUEUED' }))).toBe('préparation…');
    expect(progress(run({ totalJobs: 0, status: 'FAILED' }))).toBe('aucune branche');
    expect(isActive(run({ status: 'QUEUED' }))).toBeTrue();
    expect(isActive(run({ status: 'PARTIAL' }))).toBeFalse();
  });

  it('never presents a failed scanner as "no finding"', () => {
    expect(describeExecution(exec({}))).toBe('Trivy : 3 résultat(s)');
    expect(describeExecution(exec({ status: 'FAILED', findingsCount: 0 }))).toBe('Trivy : échec, résultats inconnus');
    expect(describeExecution(exec({ status: 'FAILED', findingsCount: 2 }))).toContain('incomplète');
    expect(describeExecution(exec({ status: 'TIMED_OUT', findingsCount: 0 }))).toContain('inconnus');
    expect(describeExecution(exec({ status: 'SKIPPED', scanner: 'pmd', errorMessage: 'not integrated in this version' })))
      .toBe('PMD : non exécuté (non intégré dans cette version)');
    expect(describeExecution(exec({ status: 'NOT_APPLICABLE', scanner: 'phpcs', findingsCount: 0, errorMessage: 'no PHP file' })))
      .toBe('PHP_CodeSniffer : rien à analyser (aucun fichier PHP)');
    expect(describeExecution(exec({ status: 'NOT_APPLICABLE', scanner: 'cppcheck', findingsCount: 0, errorMessage: 'no C / C++ file' })))
      .toBe('Cppcheck : rien à analyser (aucun fichier C / C++)');
    expect(describeExecution(exec({ status: 'SKIPPED', scanner: 'eslint', errorMessage: 'disabled in the scanner settings' })))
      .toBe('ESLint : non exécuté (désactivé dans les réglages)');
    expect(executionTone('TIMED_OUT')).toBe('warn');
    expect(executionTone('NOT_APPLICABLE')).toBe('muted');
  });

  it('formats durations, sizes, scopes and locations', () => {
    expect(formatDuration(850)).toBe('850 ms');
    expect(formatDuration(42_000)).toBe('42 s');
    expect(formatDuration(125_000)).toBe('2 min 05 s');
    expect(formatBytes(1536)).toBe('1.5 Ko');
    expect(formatBytes(null)).toBe('');
    expect(elapsed('2026-11-05T10:00:00Z', '2026-11-05T10:01:30Z')).toBe('1 min 30 s');
    expect(scopeLabel('ALL_TARGETS')).toBe('tous les dépôts sélectionnés');
    expect(scopeLabel('3 REPOSITORIES')).toBe('3 dépôt(s)');
    expect(location({ filePath: 'src/A.java', startLine: 19, packageName: null, packageVersion: null })).toBe('src/A.java:19');
    expect(location({ filePath: 'package-lock.json', startLine: null, packageName: 'lodash', packageVersion: '4.17.15' }))
      .toBe('lodash@4.17.15 — package-lock.json');
  });

  it('translates the fixed reasons and keeps the others', () => {
    expect(translateReason(null)).toBe('');
    expect(translateReason('job cancelled')).toBe('audit annulé');
    expect(translateReason('no SQL file')).toBe('aucun fichier SQL');
    expect(translateReason('java not found')).toBe('java not found');
  });

  it('never shows a missing score as a good one', () => {
    const score: ScoreView = { security: null, quality: 91.6, global: null, coverage: 35, reliability: 'INSUFFICIENT',
      formulaVersion: '1', details: {}, computedAt: '2026-11-05T10:00:00Z' };
    expect(formatScore(score.security)).toBe('—');
    expect(formatScore(score.quality)).toBe('92');
    expect(scoreTone(null)).toBe('none');
    expect(scoreTone(85)).toBe('good');
    expect(scoreTone(65)).toBe('fair');
    expect(scoreTone(40)).toBe('poor');
    expect(scoreTitle(score)).toBe('Couverture 35 % — couverture insuffisante (formule 1)');
  });
});
