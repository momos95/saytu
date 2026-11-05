package com.saytu.core.scoring;

import com.saytu.core.domain.Severity;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Parameters of the scoring formula (stored in {@code app_setting['scoring.formula']}, documented in
 * docs/scoring.md). Every field has a default; the version is recorded with each score.
 *
 * @param version            identifier stored with each snapshot
 * @param securityWeights    penalty points per OPEN security, secret or dependency finding
 * @param securityScale      security score = 100 x exp(-points / securityScale)
 * @param criticalCap        highest security score while a CRITICAL finding is open
 * @param qualityWeights     penalty points per OPEN quality finding
 * @param qualityScale       quality score = 100 x exp(-(points per 1,000 lines) / qualityScale)
 * @param bytesPerLine       average line size used to estimate lines of code from file sizes
 * @param securityShare      share of the security score in the global score (quality: the rest)
 * @param minCoverage        below this coverage (percent) of a dimension, its score is not computed
 */
public record ScoringFormula(String version, Map<Severity, Double> securityWeights, double securityScale,
                             double criticalCap, Map<Severity, Double> qualityWeights, double qualityScale,
                             double bytesPerLine, double securityShare, double minCoverage) {

    public static final ScoringFormula DEFAULT = new ScoringFormula("v1",
            weights(25, 10, 3, 1, 0), 50, 59,
            weights(10, 5, 2, 0.5, 0.1), 50,
            35, 0.6, 40);

    public ScoringFormula {
        Objects.requireNonNull(version, "version");
        securityWeights = complete(securityWeights);
        qualityWeights = complete(qualityWeights);
        if (securityScale <= 0 || qualityScale <= 0 || bytesPerLine <= 0) {
            throw new IllegalArgumentException("scales must be positive");
        }
        if (securityShare < 0 || securityShare > 1 || criticalCap < 0 || criticalCap > 100
                || minCoverage < 0 || minCoverage > 100) {
            throw new IllegalArgumentException("share, cap and coverage must be within their range");
        }
    }

    public static Map<Severity, Double> weights(double critical, double high, double medium, double low, double info) {
        Map<Severity, Double> w = new EnumMap<>(Severity.class);
        w.put(Severity.CRITICAL, critical);
        w.put(Severity.HIGH, high);
        w.put(Severity.MEDIUM, medium);
        w.put(Severity.LOW, low);
        w.put(Severity.INFO, info);
        return w;
    }

    private static Map<Severity, Double> complete(Map<Severity, Double> given) {
        Map<Severity, Double> w = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            double v = given == null || given.get(s) == null ? 0 : given.get(s);
            if (v < 0 || Double.isNaN(v)) {
                throw new IllegalArgumentException("negative weight for " + s);
            }
            w.put(s, v);
        }
        return Map.copyOf(w);
    }
}
