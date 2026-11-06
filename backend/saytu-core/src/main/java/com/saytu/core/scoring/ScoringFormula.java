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
 * @param securityScale      HYPERBOLIC: security = 100 / (1 + points / scale); EXPONENTIAL (v1): 100 x exp(-points / scale)
 * @param criticalCap        highest security score while a CRITICAL finding is open
 * @param qualityWeights     penalty points per OPEN quality finding
 * @param qualityScale       quality score = 100 x exp(-(points per 1,000 lines) / qualityScale)
 * @param bytesPerLine       average line size used to estimate lines of code from file sizes
 * @param securityShare      share of the security score in the global score (quality: the rest)
 * @param minCoverage        below this coverage (percent) of a dimension, its score is not computed
 * @param securityCurve      how points become a score (v2: HYPERBOLIC, never reaches 0)
 * @param categoryFactors    multiplier of the weight per kind of issue (code, secret, dependency, configuration)
 * @param noFixFactor        extra multiplier for a vulnerable dependency without any fixed version
 * @param diminishingReturns the n-th finding of a group (same package, same rule) counts 1/n
 */
public record ScoringFormula(String version, Map<Severity, Double> securityWeights, double securityScale,
                             double criticalCap, Map<Severity, Double> qualityWeights, double qualityScale,
                             double bytesPerLine, double securityShare, double minCoverage, SecurityCurve securityCurve,
                             Map<SecurityIssue.Category, Double> categoryFactors, double noFixFactor,
                             boolean diminishingReturns) {

    public enum SecurityCurve { EXPONENTIAL, HYPERBOLIC }

    /** Phase 5 formula, kept to document and reproduce old snapshots. */
    public static final ScoringFormula V1 = new ScoringFormula("v1",
            weights(25, 10, 3, 1, 0), 50, 59,
            weights(10, 5, 2, 0.5, 0.1), 50,
            35, 0.6, 40, SecurityCurve.EXPONENTIAL, factors(1, 1, 1, 1), 1, false);

    /** Current default (docs/scoring.md). */
    public static final ScoringFormula DEFAULT = new ScoringFormula("v2",
            weights(25, 10, 3, 1, 0), 100, 59,
            weights(10, 5, 2, 0.5, 0.1), 50,
            35, 0.6, 40, SecurityCurve.HYPERBOLIC, factors(1, 1, 1, 0.5), 0.5, true);

    public ScoringFormula {
        Objects.requireNonNull(version, "version");
        securityWeights = complete(securityWeights);
        qualityWeights = complete(qualityWeights);
        securityCurve = securityCurve == null ? SecurityCurve.HYPERBOLIC : securityCurve;
        categoryFactors = completeFactors(categoryFactors);
        if (noFixFactor < 0 || noFixFactor > 1 || Double.isNaN(noFixFactor)) {
            throw new IllegalArgumentException("noFixFactor must be within [0, 1]");
        }
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

    public static Map<SecurityIssue.Category, Double> factors(double code, double secret, double dependency,
                                                              double configuration) {
        Map<SecurityIssue.Category, Double> f = new EnumMap<>(SecurityIssue.Category.class);
        f.put(SecurityIssue.Category.CODE, code);
        f.put(SecurityIssue.Category.SECRET, secret);
        f.put(SecurityIssue.Category.DEPENDENCY, dependency);
        f.put(SecurityIssue.Category.CONFIGURATION, configuration);
        return f;
    }

    private static Map<SecurityIssue.Category, Double> completeFactors(Map<SecurityIssue.Category, Double> given) {
        Map<SecurityIssue.Category, Double> f = new EnumMap<>(SecurityIssue.Category.class);
        for (SecurityIssue.Category c : SecurityIssue.Category.values()) {
            double v = given == null || given.get(c) == null ? 1 : given.get(c);
            if (v < 0 || v > 10 || Double.isNaN(v)) {
                throw new IllegalArgumentException("category factor out of range for " + c);
            }
            f.put(c, v);
        }
        return Map.copyOf(f);
    }

    /** Security score (0..100) for the given penalty points, before the critical cap. */
    public double securityScore(double points) {
        return securityCurve == SecurityCurve.HYPERBOLIC
                ? 100 / (1 + points / securityScale)
                : 100 * Math.exp(-points / securityScale);
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
