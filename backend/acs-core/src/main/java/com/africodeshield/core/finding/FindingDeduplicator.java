package com.africodeshield.core.finding;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Merges findings that share a fingerprint (same issue reported by several scanners, or several
 * times by the same scanner).
 * <p>
 * Merge policy: the most severe report becomes the primary; CWEs and references are unioned; the
 * first non-empty recommendation and CVSS data are kept. Every original report is preserved in
 * {@link Merged#sources()} so it can be stored as a {@code finding_occurrence}.
 */
public final class FindingDeduplicator {

    private FindingDeduplicator() {
    }

    public static List<Merged> deduplicate(List<NormalizedFinding> findings) {
        Map<String, List<NormalizedFinding>> byFingerprint = new LinkedHashMap<>();
        for (NormalizedFinding f : findings) {
            byFingerprint.computeIfAbsent(f.fingerprint(), k -> new ArrayList<>()).add(f);
        }
        List<Merged> result = new ArrayList<>(byFingerprint.size());
        byFingerprint.forEach((fp, group) -> result.add(merge(fp, group)));
        return result;
    }

    private static Merged merge(String fingerprint, List<NormalizedFinding> group) {
        List<NormalizedFinding> sorted = group.stream()
                // Severity enum is ordered most severe first; stable sort keeps scanner order on ties
                .sorted(Comparator.comparing(NormalizedFinding::severity))
                .toList();
        NormalizedFinding primary = sorted.getFirst();
        if (sorted.size() == 1) {
            return new Merged(fingerprint, primary, List.copyOf(group));
        }
        Set<String> cwes = new LinkedHashSet<>();
        Set<String> references = new LinkedHashSet<>();
        String recommendation = null;
        Double cvss = primary.cvssScore();
        String cvssVector = primary.cvssVector();
        String cve = primary.cve();
        for (NormalizedFinding f : sorted) {
            cwes.addAll(f.cwes());
            references.addAll(f.references());
            if (recommendation == null && f.recommendation() != null && !f.recommendation().isBlank()) {
                recommendation = f.recommendation();
            }
            if (cvss == null && f.cvssScore() != null) {
                cvss = f.cvssScore();
                cvssVector = f.cvssVector();
            }
            if ((cve == null || cve.isBlank()) && f.cve() != null) {
                cve = f.cve();
            }
        }
        NormalizedFinding merged = new NormalizedFinding(
                primary.scanner(), primary.ruleId(), primary.type(), primary.severity(), primary.title(),
                primary.description(), primary.location(), List.copyOf(cwes), cve, cvss, cvssVector,
                primary.dependency(), primary.evidence(), recommendation, List.copyOf(references),
                primary.contextHash());
        return new Merged(fingerprint, merged, List.copyOf(group));
    }

    /**
     * @param fingerprint stable id shared by all sources
     * @param finding     merged view
     * @param sources     every original report (one per scanner/rule hit)
     */
    public record Merged(String fingerprint, NormalizedFinding finding, List<NormalizedFinding> sources) {
    }
}
