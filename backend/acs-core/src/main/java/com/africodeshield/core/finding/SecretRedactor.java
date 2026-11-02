package com.africodeshield.core.finding;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Removes secrets from evidence snippets before they are persisted, displayed, exported in a
 * report or sent to a webhook / local LLM.
 * <p>
 * Two layers:
 * <ol>
 *   <li>exact values reported by the scanner (e.g. Gitleaks {@code Secret} field) are masked;</li>
 *   <li>generic patterns (private keys, cloud keys, bearer tokens, credential assignments) are
 *       masked even when the producing scanner is not a secret scanner.</li>
 * </ol>
 * A short prefix is kept for known secrets so that a human can still recognise which key leaked.
 */
public final class SecretRedactor {

    public static final String REDACTED = "[REDACTED]";

    /** Maximum number of clear characters kept at the start of a known secret. */
    private static final int KEPT_PREFIX = 4;
    /** Secrets shorter than this are fully masked. */
    private static final int MIN_LENGTH_FOR_PREFIX = 12;

    private static final Pattern PRIVATE_KEY_BLOCK = Pattern.compile(
            "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\\z)",
            Pattern.DOTALL);

    private static final List<Pattern> TOKEN_PATTERNS = List.of(
            // AWS access key id
            Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"),
            // GitHub tokens (classic, fine-grained, app, oauth)
            Pattern.compile("\\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\\b"),
            // GitLab personal / project / group tokens
            Pattern.compile("\\bglpat-[A-Za-z0-9_\\-]{20,}\\b"),
            // Slack tokens
            Pattern.compile("\\bxox[abprs]-[A-Za-z0-9-]{10,}\\b"),
            // Google API key
            Pattern.compile("\\bAIza[0-9A-Za-z_\\-]{35}\\b"),
            // JSON Web Tokens
            Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"),
            // Credentials embedded in URLs: scheme://user:password@host
            Pattern.compile("(?<=://)[^\\s:/@]+:[^\\s@/]+(?=@)")
    );

    /** key = value / key: value assignments of sensitive-looking keys; the value is group 2. */
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|authorization)"
                    + "[\"']?\\s*[:=]\\s*(?:bearer\\s+|basic\\s+)?[\"']?)([^\\s\"',;]{4,})");

    private static final Pattern BEARER = Pattern.compile("(?i)(\\bbearer\\s+)([A-Za-z0-9._~+/=-]{8,})");

    private SecretRedactor() {
    }

    /**
     * Redacts {@code text}.
     *
     * @param text         evidence; {@code null} returns {@code null}
     * @param knownSecrets exact secret values reported by the scanner (may be empty)
     */
    public static String redact(String text, Collection<String> knownSecrets) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String result = text;
        if (knownSecrets != null && !knownSecrets.isEmpty()) {
            // longest first so that a secret containing another one is masked entirely
            List<String> ordered = knownSecrets.stream()
                    .filter(Objects::nonNull)
                    .filter(s -> !s.isBlank())
                    .distinct()
                    .sorted(Comparator.comparingInt(String::length).reversed())
                    .toList();
            for (String secret : ordered) {
                result = result.replace(secret, mask(secret));
            }
        }
        result = PRIVATE_KEY_BLOCK.matcher(result).replaceAll(Matcher.quoteReplacement(REDACTED + " PRIVATE KEY"));
        for (Pattern pattern : TOKEN_PATTERNS) {
            result = pattern.matcher(result).replaceAll(Matcher.quoteReplacement(REDACTED));
        }
        result = BEARER.matcher(result).replaceAll(m -> Matcher.quoteReplacement(m.group(1) + REDACTED));
        result = ASSIGNMENT.matcher(result).replaceAll(m -> {
            String value = m.group(2);
            if (value.contains("[REDACTED")) {
                return Matcher.quoteReplacement(m.group(0));
            }
            return Matcher.quoteReplacement(m.group(1) + REDACTED);
        });
        return result;
    }

    public static String redact(String text) {
        return redact(text, List.of());
    }

    /** Masks one known secret, keeping a short prefix when the secret is long enough. */
    static String mask(String secret) {
        if (secret.length() < MIN_LENGTH_FOR_PREFIX) {
            return REDACTED;
        }
        return secret.substring(0, KEPT_PREFIX) + "…" + REDACTED;
    }
}
