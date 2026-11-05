package com.saytu.core.scoring;

import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Scoring formula v1 (docs/scoring.md).
 * <p>
 * <b>Security</b> (absolute: one critical vulnerability matters whatever the size of the code):
 * points = Σ weight(severity) over OPEN security, secret and dependency findings;
 * score = 100 × exp(−points / scale), capped while a CRITICAL finding is open.
 * <p>
 * <b>Quality</b> (relative to size): density = Σ weight(severity) per 1,000 estimated lines of code;
 * score = 100 × exp(−density / scale).
 * <p>
 * <b>Coverage</b> says which part of the expected analyses really ran: Opengrep, Trivy and Gitleaks
 * for security; for quality, the share of the code (by size) written in a language whose quality
 * tool succeeded. A scanner that failed, timed out, was disabled or does not exist for a language
 * lowers the coverage; it never counts as "no problem". A dimension whose coverage is below the
 * formula's minimum gets no score.
 */
public final class ScoreCalculator {

    /** Security analyses and their share of the security coverage. */
    static final Map<ScannerId, Double> SECURITY_SCANNERS = Map.of(
            ScannerId.OPENGREP, 0.40, ScannerId.TRIVY, 0.35, ScannerId.GITLEAKS, 0.25);

    /** Quality tools per language; a language is covered when at least one of its tools succeeded. */
    public static final Map<Language, Set<ScannerId>> QUALITY_TOOLS = qualityTools();

    private static Map<Language, Set<ScannerId>> qualityTools() {
        Map<Language, Set<ScannerId>> m = new EnumMap<>(Language.class);
        m.put(Language.JAVA, Set.of(ScannerId.CHECKSTYLE, ScannerId.PMD));
        m.put(Language.TYPESCRIPT, Set.of(ScannerId.ESLINT));
        m.put(Language.JAVASCRIPT, Set.of(ScannerId.ESLINT));
        m.put(Language.PHP, Set.of(ScannerId.PHPCS));
        m.put(Language.C, Set.of(ScannerId.CPPCHECK));
        m.put(Language.CPP, Set.of(ScannerId.CPPCHECK));
        m.put(Language.SQL, Set.of(ScannerId.SQLFLUFF));
        return Map.copyOf(m);
    }

    private final ScoringFormula formula;

    public ScoreCalculator(ScoringFormula formula) {
        this.formula = formula;
    }

    public ScoringFormula formula() {
        return formula;
    }

    public Score branch(BranchScoreInput in) {
        Map<String, Object> details = new LinkedHashMap<>();

        // ---- security
        double securityCoverage = 0;
        List<String> missingSecurity = new ArrayList<>();
        for (var e : SECURITY_SCANNERS.entrySet()) {
            if (in.succeeded(e.getKey())) {
                securityCoverage += e.getValue();
            } else {
                missingSecurity.add(e.getKey().key());
            }
        }
        securityCoverage *= 100;
        double securityPoints = points(in.security(), formula.securityWeights());
        Double security = null;
        if (securityCoverage >= formula.minCoverage()) {
            security = 100 * Math.exp(-securityPoints / formula.securityScale());
            if (in.security().get(Severity.CRITICAL) > 0) {
                security = Math.min(security, formula.criticalCap());
            }
            security = round(security);
        }

        // ---- quality
        LanguageProfile langs = in.languages();
        long codeBytes = 0;
        long coveredBytes = 0;
        List<String> uncovered = new ArrayList<>();
        for (var e : langs.stats().entrySet()) {
            if (e.getKey().kind() != Language.Kind.CODE) {
                continue;
            }
            long bytes = e.getValue().bytes();
            codeBytes += bytes;
            Set<ScannerId> tools = QUALITY_TOOLS.getOrDefault(e.getKey(), Set.of());
            if (tools.stream().anyMatch(in::succeeded)) {
                coveredBytes += bytes;
            } else {
                uncovered.add(e.getKey().key());
            }
        }
        boolean hasCode = codeBytes > 0;
        double qualityCoverage = hasCode ? 100.0 * coveredBytes / codeBytes : 0;
        double kloc = Math.max(1, codeBytes / formula.bytesPerLine() / 1000);
        double qualityPoints = points(in.quality(), formula.qualityWeights());
        Double quality = null;
        if (hasCode && qualityCoverage >= formula.minCoverage()) {
            quality = round(100 * Math.exp(-(qualityPoints / kloc) / formula.qualityScale()));
        }

        // ---- global and coverage
        double coverage = hasCode
                ? formula.securityShare() * securityCoverage + (1 - formula.securityShare()) * qualityCoverage
                : securityCoverage;
        Double global = combine(security, quality);

        details.put("formula", formula.version());
        details.put("securityPoints", round(securityPoints));
        details.put("securityCoverage", round(securityCoverage));
        details.put("qualityPoints", round(qualityPoints));
        details.put("estimatedKloc", round(kloc));
        details.put("qualityCoverage", hasCode ? round(qualityCoverage) : null);
        details.put("missingSecurityScanners", missingSecurity.stream().sorted().toList());
        details.put("languagesWithoutQualityAnalysis", uncovered.stream().sorted().toList());
        details.put("openSecurity", counts(in.security()));
        details.put("openQuality", counts(in.quality()));
        return new Score(security, quality, global, round(coverage), Reliability.of(coverage, formula.minCoverage()), details);
    }

    /** Weighted item for aggregation (repository: branches; organisation and global: repositories). */
    public record Weighted(Score score, double weight) {
    }

    /**
     * Repository score: its weakest branch (lowest global score); coverage and reliability: the
     * lowest among its branches.
     */
    public Score weakest(List<Score> branches) {
        if (branches.isEmpty()) {
            return null;
        }
        Score worst = branches.getFirst();
        double minCoverage = 100;
        for (Score s : branches) {
            minCoverage = Math.min(minCoverage, s.coverage());
            if (rank(s) < rank(worst)) {
                worst = s;
            }
        }
        Map<String, Object> details = new LinkedHashMap<>(worst.details());
        details.put("aggregation", "weakest branch of " + branches.size());
        return new Score(worst.security(), worst.quality(), worst.global(), round(minCoverage),
                Reliability.of(minCoverage, formula.minCoverage()), details);
    }

    /** Organisation / global score: averages weighted by code size, over the scores that exist. */
    public Score weightedAverage(List<Weighted> items) {
        if (items.isEmpty()) {
            return null;
        }
        double totalWeight = 0;
        double coverage = 0;
        double[] sec = new double[2];
        double[] qual = new double[2];
        for (Weighted w : items) {
            double weight = Math.max(w.weight(), 1);
            totalWeight += weight;
            coverage += w.score().coverage() * weight;
            if (w.score().security() != null) {
                sec[0] += w.score().security() * weight;
                sec[1] += weight;
            }
            if (w.score().quality() != null) {
                qual[0] += w.score().quality() * weight;
                qual[1] += weight;
            }
        }
        coverage /= totalWeight;
        Double security = sec[1] > 0 ? round(sec[0] / sec[1]) : null;
        Double quality = qual[1] > 0 ? round(qual[0] / qual[1]) : null;
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("formula", formula.version());
        details.put("aggregation", "average weighted by code size of " + items.size() + " repositories");
        details.put("repositoriesWithSecurityScore", (int) items.stream().filter(i -> i.score().security() != null).count());
        details.put("repositoriesWithQualityScore", (int) items.stream().filter(i -> i.score().quality() != null).count());
        return new Score(security, quality, combine(security, quality), round(coverage),
                Reliability.of(coverage, formula.minCoverage()), details);
    }

    private Double combine(Double security, Double quality) {
        if (security != null && quality != null) {
            return round(formula.securityShare() * security + (1 - formula.securityShare()) * quality);
        }
        return security != null ? security : quality;
    }

    /** Lower is worse; a missing score ranks as the worst. */
    private static double rank(Score s) {
        return s.global() == null ? -1 : s.global();
    }

    private static double points(Map<Severity, Long> counts, Map<Severity, Double> weights) {
        double p = 0;
        for (Severity s : Severity.values()) {
            p += counts.get(s) * weights.get(s);
        }
        return p;
    }

    private static Map<String, Long> counts(Map<Severity, Long> counts) {
        Map<String, Long> m = new LinkedHashMap<>();
        for (Severity s : Severity.values()) {
            m.put(s.name(), counts.get(s));
        }
        return m;
    }

    static double round(double v) {
        return Math.round(v * 100) / 100.0;
    }
}
