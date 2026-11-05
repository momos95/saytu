package com.saytu.core.scoring;

import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import org.junit.jupiter.api.Test;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScoreCalculatorTest {

    private final ScoreCalculator calc = new ScoreCalculator(ScoringFormula.DEFAULT);

    private static final ScannerExecutionStatus OK = ScannerExecutionStatus.SUCCEEDED;

    private static Map<ScannerId, ScannerExecutionStatus> ran(Object... pairs) {
        Map<ScannerId, ScannerExecutionStatus> m = new EnumMap<>(ScannerId.class);
        for (int i = 0; i < pairs.length; i += 2) {
            m.put((ScannerId) pairs[i], (ScannerExecutionStatus) pairs[i + 1]);
        }
        return m;
    }

    private static Map<ScannerId, ScannerExecutionStatus> allOk() {
        return ran(ScannerId.OPENGREP, OK, ScannerId.TRIVY, OK, ScannerId.GITLEAKS, OK, ScannerId.CHECKSTYLE, OK,
                ScannerId.PMD, OK, ScannerId.ESLINT, OK);
    }

    /** 35 kB of Java (~1,000 lines) and 35 kB of TypeScript. */
    private static LanguageProfile javaAndTs() {
        return new LanguageProfile(Map.of(Language.JAVA, new LanguageProfile.Stats(20, 35_000),
                Language.TYPESCRIPT, new LanguageProfile.Stats(10, 35_000)), 40);
    }

    private static Map<Severity, Long> counts(long critical, long high, long medium, long low, long info) {
        return Map.of(Severity.CRITICAL, critical, Severity.HIGH, high, Severity.MEDIUM, medium, Severity.LOW, low,
                Severity.INFO, info);
    }

    @Test
    void cleanAndFullyCoveredBranchScoresHundred() {
        Score s = calc.branch(new BranchScoreInput(Map.of(), Map.of(), javaAndTs(), allOk()));
        assertEquals(100.0, s.security());
        assertEquals(100.0, s.quality());
        assertEquals(100.0, s.global());
        assertEquals(100.0, s.coverage());
        assertEquals(Reliability.HIGH, s.reliability());
    }

    @Test
    void securityPenaltiesAndCriticalCap() {
        Score oneHigh = calc.branch(new BranchScoreInput(counts(0, 1, 0, 0, 0), Map.of(), javaAndTs(), allOk()));
        assertEquals(81.87, oneHigh.security());
        Score oneCritical = calc.branch(new BranchScoreInput(counts(1, 0, 0, 0, 0), Map.of(), javaAndTs(), allOk()));
        assertEquals(59.0, oneCritical.security(), "exp gives 60.65, capped while a CRITICAL is open");
        Score many = calc.branch(new BranchScoreInput(counts(2, 10, 20, 0, 0), Map.of(), javaAndTs(), allOk()));
        assertTrue(many.security() < 5);
        assertEquals(many.global(), Math.round((0.6 * many.security() + 0.4 * many.quality()) * 100) / 100.0);
    }

    @Test
    void qualityIsRelativeToCodeSize() {
        // 20 LOW + 50 INFO = 15 points on 2,000 lines -> density 7.5 -> 86.07
        Score small = calc.branch(new BranchScoreInput(Map.of(), counts(0, 0, 0, 20, 50), javaAndTs(), allOk()));
        assertEquals(86.07, small.quality());
        LanguageProfile big = new LanguageProfile(Map.of(Language.JAVA, new LanguageProfile.Stats(500, 3_500_000)), 500);
        Score large = calc.branch(new BranchScoreInput(Map.of(), counts(0, 0, 0, 20, 50), big, allOk()));
        assertTrue(large.quality() > small.quality(), "same findings weigh less in a larger code base");
    }

    @Test
    void scannersThatDidNotRunLowerCoverageNotTheFindings() {
        Map<ScannerId, ScannerExecutionStatus> trivyFailed = allOk();
        trivyFailed.put(ScannerId.TRIVY, ScannerExecutionStatus.FAILED);
        Score s = calc.branch(new BranchScoreInput(Map.of(), Map.of(), javaAndTs(), trivyFailed));
        assertEquals(100.0, s.security(), "the findings that exist are scored...");
        assertEquals(79.0, s.coverage(), "...but coverage drops: 0.6 x 65 + 0.4 x 100");
        assertEquals(Reliability.MEDIUM, s.reliability());
        assertEquals(List.of("trivy"), s.details().get("missingSecurityScanners"));

        Score nothing = calc.branch(new BranchScoreInput(Map.of(), Map.of(), javaAndTs(),
                ran(ScannerId.OPENGREP, ScannerExecutionStatus.TIMED_OUT, ScannerId.TRIVY, ScannerExecutionStatus.FAILED)));
        assertNull(nothing.security(), "no security score below the minimum coverage");
        assertNull(nothing.quality());
        assertNull(nothing.global());
        assertEquals(Reliability.INSUFFICIENT, nothing.reliability());
    }

    @Test
    void languagesWithoutQualityToolAreUncovered() {
        LanguageProfile csharpAndJava = new LanguageProfile(Map.of(Language.CSHARP, new LanguageProfile.Stats(30, 60_000),
                Language.JAVA, new LanguageProfile.Stats(10, 40_000)), 40);
        Score s = calc.branch(new BranchScoreInput(Map.of(), Map.of(), csharpAndJava, allOk()));
        assertEquals(40.0, s.details().get("qualityCoverage"));
        assertEquals(100.0, s.quality(), "40 % meets the minimum");
        assertEquals(List.of("csharp"), s.details().get("languagesWithoutQualityAnalysis"));
        assertEquals(76.0, s.coverage());

        LanguageProfile onlyCsharp = new LanguageProfile(Map.of(Language.CSHARP, new LanguageProfile.Stats(30, 60_000)), 30);
        Score c = calc.branch(new BranchScoreInput(Map.of(), Map.of(), onlyCsharp, allOk()));
        assertNull(c.quality());
        assertEquals(c.security(), c.global(), "global falls back to the available dimension");
    }

    @Test
    void repositoryWithoutCodeIsJudgedOnSecurityOnly() {
        LanguageProfile infra = new LanguageProfile(Map.of(Language.DOCKERFILE, new LanguageProfile.Stats(1, 300),
                Language.TERRAFORM, new LanguageProfile.Stats(3, 4000)), 4);
        Score s = calc.branch(new BranchScoreInput(counts(0, 0, 1, 0, 0), Map.of(), infra, allOk()));
        assertNull(s.quality());
        assertEquals(100.0, s.coverage());
        assertEquals(s.security(), s.global());
    }

    @Test
    void aggregation() {
        Score good = new Score(90.0, 80.0, 86.0, 100, Reliability.HIGH, Map.of());
        Score bad = new Score(40.0, 70.0, 52.0, 75, Reliability.MEDIUM, Map.of());
        Score repo = calc.weakest(List.of(good, bad));
        assertEquals(52.0, repo.global());
        assertEquals(75.0, repo.coverage());
        assertEquals(Reliability.MEDIUM, repo.reliability());

        Score org = calc.weightedAverage(List.of(new ScoreCalculator.Weighted(good, 3000), new ScoreCalculator.Weighted(bad, 1000)));
        assertEquals(77.5, org.security());
        assertEquals(77.5, org.quality());
        assertEquals(93.75, org.coverage());
        Score withMissing = calc.weightedAverage(List.of(new ScoreCalculator.Weighted(good, 1),
                new ScoreCalculator.Weighted(new Score(null, null, null, 20, Reliability.INSUFFICIENT, Map.of()), 1)));
        assertEquals(90.0, withMissing.security(), "repositories without a score do not count as 0 nor 100");
        assertEquals(60.0, withMissing.coverage());
    }
}
