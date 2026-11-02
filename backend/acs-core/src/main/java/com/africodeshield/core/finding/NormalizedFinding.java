package com.africodeshield.core.finding;

import com.africodeshield.core.domain.FindingType;
import com.africodeshield.core.domain.ScannerId;
import com.africodeshield.core.domain.Severity;

import java.util.List;
import java.util.Objects;

/**
 * Scanner-agnostic finding produced by a {@code ScannerAdapter} parser, before persistence.
 * <p>
 * Invariant: {@code evidence} is always passed through {@link SecretRedactor} by the canonical
 * constructor. Adapters additionally redact the exact secret values reported by the tool, so raw
 * secrets never leave the adapter.
 *
 * @param scanner         producing scanner
 * @param ruleId          tool rule identifier (e.g. {@code java.lang.security.audit.sqli...}, {@code CVE-2024-1234})
 * @param type            finding type
 * @param severity        normalised severity
 * @param title           short human-readable title
 * @param description     long description from the rule (may be empty)
 * @param location        file / lines, {@code null} for repository-wide findings
 * @param cwes            CWE identifiers, normalised as {@code CWE-79}
 * @param cve             CVE / GHSA identifier for dependency findings
 * @param cvssScore       CVSS base score, {@code null} if unknown
 * @param cvssVector      CVSS vector, {@code null} if unknown
 * @param dependency      vulnerable package, for DEPENDENCY findings
 * @param evidence        redacted code snippet / match
 * @param recommendation  deterministic recommendation from the rule metadata
 * @param references      reference URLs (advisories, rule docs)
 * @param contextHash     hash of the normalised code around the finding, used for stable fingerprints
 */
public record NormalizedFinding(
        ScannerId scanner,
        String ruleId,
        FindingType type,
        Severity severity,
        String title,
        String description,
        SourceLocation location,
        List<String> cwes,
        String cve,
        Double cvssScore,
        String cvssVector,
        Dependency dependency,
        String evidence,
        String recommendation,
        List<String> references,
        String contextHash) {

    public NormalizedFinding {
        Objects.requireNonNull(scanner, "scanner");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(severity, "severity");
        if (ruleId == null || ruleId.isBlank()) {
            throw new IllegalArgumentException("ruleId is required");
        }
        if (title == null || title.isBlank()) {
            title = ruleId;
        }
        if (cvssScore != null && (cvssScore < 0.0 || cvssScore > 10.0)) {
            throw new IllegalArgumentException("cvssScore out of range: " + cvssScore);
        }
        if (type == FindingType.DEPENDENCY && dependency == null) {
            throw new IllegalArgumentException("DEPENDENCY findings require a dependency");
        }
        cwes = cwes == null ? List.of() : cwes.stream().map(Cwe::normalize).filter(Objects::nonNull).distinct().toList();
        references = references == null ? List.of() : List.copyOf(references);
        description = description == null ? "" : description;
        // Defence in depth: adapters redact known secret values; generic patterns are always applied.
        evidence = SecretRedactor.redact(evidence);
    }

    /** Computes the stable fingerprint used to deduplicate and track this finding over time. */
    public String fingerprint() {
        return FindingFingerprint.of(this);
    }

    /** Location of a finding in the analysed tree. Paths are relative to the repository root. */
    public record SourceLocation(String path, Integer startLine, Integer endLine) {
        public SourceLocation {
            if (path == null || path.isBlank()) {
                throw new IllegalArgumentException("path is required");
            }
            path = FindingFingerprint.normalizePath(path);
            if (startLine != null && startLine < 1) {
                throw new IllegalArgumentException("startLine must be >= 1");
            }
            if (endLine != null && startLine != null && endLine < startLine) {
                endLine = startLine;
            }
        }
    }

    /** Vulnerable third-party package. */
    public record Dependency(String ecosystem, String name, String installedVersion, String fixedVersion) {
        public Dependency {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("dependency name is required");
            }
        }
    }

    /** CWE helpers. */
    public static final class Cwe {
        private Cwe() {
        }

        /** Normalises "79", "cwe-79", "CWE-79: Improper Neutralization..." to "CWE-79"; returns null if invalid. */
        public static String normalize(String raw) {
            if (raw == null) {
                return null;
            }
            var m = java.util.regex.Pattern.compile("(?i)^\\s*(?:cwe[-_ ]?)?(\\d{1,5})\\b").matcher(raw);
            return m.find() ? "CWE-" + Integer.parseInt(m.group(1)) : null;
        }
    }
}
