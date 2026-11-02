package com.africodeshield.core.domain;

import java.util.Locale;
import java.util.Optional;

/**
 * Normalised severity, shared by every scanner.
 * <p>
 * Ordered from most to least severe: {@code compareTo} &lt; 0 means "more severe".
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO;

    public boolean isAtLeast(Severity threshold) {
        return this.ordinal() <= threshold.ordinal();
    }

    /**
     * Maps a CVSS v3/v4 base score to a severity using the FIRST qualitative scale.
     * 0.0 is mapped to {@link #INFO}.
     */
    public static Severity fromCvss(double score) {
        if (Double.isNaN(score) || score < 0.0 || score > 10.0) {
            throw new IllegalArgumentException("CVSS score must be within [0.0, 10.0]: " + score);
        }
        if (score >= 9.0) {
            return CRITICAL;
        }
        if (score >= 7.0) {
            return HIGH;
        }
        if (score >= 4.0) {
            return MEDIUM;
        }
        if (score > 0.0) {
            return LOW;
        }
        return INFO;
    }

    /**
     * Lenient parser for the labels emitted by the integrated tools
     * (e.g. "ERROR"/"WARNING" for Opengrep, "UNKNOWN" for Trivy).
     */
    public static Optional<Severity> parseLenient(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        return switch (raw.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "BLOCKER" -> Optional.of(CRITICAL);
            case "HIGH", "ERROR", "MAJOR" -> Optional.of(HIGH);
            case "MEDIUM", "MODERATE", "WARNING", "WARN" -> Optional.of(MEDIUM);
            case "LOW", "MINOR" -> Optional.of(LOW);
            case "INFO", "INFORMATIONAL", "NOTE", "NONE", "UNKNOWN" -> Optional.of(INFO);
            default -> Optional.empty();
        };
    }
}
