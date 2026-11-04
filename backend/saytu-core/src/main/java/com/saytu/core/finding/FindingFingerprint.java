package com.saytu.core.finding;

import com.saytu.core.domain.FindingType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Stable identifier of a finding within a (repository, branch).
 * <p>
 * The fingerprint must survive unrelated edits (lines shifting) and be identical when two scanners
 * report the same issue, so that results are deduplicated. Rules (documented in docs/data-model.md):
 * <ul>
 *   <li><b>DEPENDENCY</b>: ecosystem + package + installed version + vulnerability id. The manifest
 *       path is deliberately excluded: Trivy (lockfile) and Dependency-Check (jar) report different
 *       paths for the same vulnerable package.</li>
 *   <li><b>SECRET</b>: path + hash of the secret (provided by the adapter as {@code contextHash}),
 *       never the secret itself.</li>
 *   <li><b>SECURITY / QUALITY</b>: type + weakness key + path + context hash, where the weakness key
 *       is the first CWE when available (enables cross-tool deduplication) or {@code scanner:rule}.
 *       The context hash is computed from the normalised source line, not the line number.</li>
 * </ul>
 * Output: 64 lowercase hex characters (SHA-256).
 */
public final class FindingFingerprint {

    private static final String VERSION = "v1";

    private FindingFingerprint() {
    }

    public static String of(NormalizedFinding f) {
        String material = switch (f.type()) {
            case DEPENDENCY -> String.join("|",
                    "dep",
                    lower(f.dependency().ecosystem()),
                    lower(f.dependency().name()),
                    nullToEmpty(f.dependency().installedVersion()),
                    vulnerabilityKey(f));
            case SECRET -> String.join("|",
                    "secret",
                    pathOf(f),
                    f.contextHash() != null ? f.contextHash() : f.ruleId() + "@" + lineOf(f));
            case SECURITY, QUALITY -> String.join("|",
                    f.type().name().toLowerCase(Locale.ROOT),
                    weaknessKey(f),
                    pathOf(f),
                    f.contextHash() != null ? f.contextHash() : "L" + lineOf(f));
        };
        return sha256Hex(VERSION + "|" + material);
    }

    /**
     * Hash of a source line, insensitive to indentation and whitespace changes. Used by the
     * orchestrator to fill {@link NormalizedFinding#contextHash()} for code findings.
     */
    public static String contextHash(String sourceLine) {
        String normalized = sourceLine == null ? "" : sourceLine.strip().replaceAll("\\s+", " ");
        return sha256Hex(normalized).substring(0, 16);
    }

    /** Normalises a repository-relative path: forward slashes, no leading "./" or "/". */
    public static String normalizePath(String path) {
        String p = path.replace('\\', '/').strip().replaceAll("/{2,}", "/");
        String previous;
        do {
            previous = p;
            p = p.replace("/./", "/");
            if (p.startsWith("./")) {
                p = p.substring(2);
            }
            if (p.startsWith("/")) {
                p = p.substring(1);
            }
        } while (!p.equals(previous));
        return p;
    }

    private static String vulnerabilityKey(NormalizedFinding f) {
        if (f.cve() != null && !f.cve().isBlank()) {
            return f.cve().strip().toUpperCase(Locale.ROOT);
        }
        return f.ruleId().strip().toUpperCase(Locale.ROOT);
    }

    private static String weaknessKey(NormalizedFinding f) {
        if (f.type() == FindingType.SECURITY && !f.cwes().isEmpty()) {
            return f.cwes().getFirst();
        }
        return f.scanner().key() + ":" + f.ruleId();
    }

    private static String pathOf(NormalizedFinding f) {
        return f.location() == null ? "" : f.location().path();
    }

    private static String lineOf(NormalizedFinding f) {
        return f.location() == null || f.location().startLine() == null ? "0" : f.location().startLine().toString();
    }

    private static String lower(String s) {
        return s == null ? "" : s.strip().toLowerCase(Locale.ROOT);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s.strip();
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
