package com.saytu.git.http;

import com.saytu.core.finding.SecretRedactor;
import com.saytu.core.git.GitProviderException;
import com.saytu.core.git.GitProviderException.Kind;
import com.saytu.git.json.JsonNode;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Turns HTTP statuses and I/O failures into typed {@link GitProviderException}s that the UI can act on.
 * Messages are built from fixed text plus provider error messages passed through {@link SecretRedactor}
 * and truncated: they never contain request headers, hence never the token.
 */
public final class HttpErrorClassifier {

    private static final int MAX_PROVIDER_MESSAGE = 200;
    /** Values above this are epoch seconds, below are delays in seconds. */
    private static final long EPOCH_THRESHOLD = 1_000_000_000L;
    private static final Duration MAX_RETRY_AFTER = Duration.ofHours(24);

    private HttpErrorClassifier() {
    }

    public static GitProviderException fromResponse(int status, Map<String, List<String>> headers, JsonNode body,
                                                    URI uri, Clock clock) {
        String providerMessage = providerMessage(body).map(m -> " Platform says: " + m).orElse("");
        String where = uri.getHost();
        if (status >= 300 && status < 400) {
            String location = header(headers, "location").map(HttpErrorClassifier::hostOf).orElse("?");
            return new GitProviderException(Kind.UNEXPECTED_RESPONSE, "HTTP " + status + " redirect to " + location
                    + " was not followed (tokens are never forwarded). Check the URL: https vs http, "
                    + "trailing path, or set the API URL explicitly.");
        }
        Optional<Duration> retryAfter = retryAfter(headers, clock);
        boolean rateLimitHeaders = retryAfter.isPresent()
                || header(headers, "x-ratelimit-remaining").map("0"::equals).orElse(false);
        return switch (status) {
            case 401 -> new GitProviderException(Kind.AUTHENTICATION_FAILED, "Authentication rejected by " + where
                    + " (401): the token is missing, invalid, expired or revoked." + providerMessage);
            case 403 -> rateLimitHeaders
                    ? rateLimited(where, retryAfter, providerMessage)
                    : new GitProviderException(Kind.INSUFFICIENT_PERMISSIONS, "Access denied by " + where
                    + " (403): the token lacks a scope or the account lacks a permission." + providerMessage);
            case 404 -> new GitProviderException(Kind.NOT_FOUND, "Not found on " + where + " (404): wrong URL, "
                    + "or the resource is invisible to this token." + providerMessage);
            case 429 -> rateLimited(where, retryAfter, providerMessage);
            default -> status >= 500
                    ? new GitProviderException(Kind.SERVER_ERROR, where + " returned HTTP " + status
                    + " (server error), retry later." + providerMessage, retryAfter.orElse(null), null)
                    : new GitProviderException(Kind.UNEXPECTED_RESPONSE, where + " returned unexpected HTTP "
                    + status + "." + providerMessage);
        };
    }

    public static GitProviderException fromIOException(IOException e, URI uri) {
        String host = uri.getHost();
        if (e instanceof SSLException) {
            return new GitProviderException(Kind.TLS_ERROR, "TLS handshake with " + host + " failed: the certificate "
                    + "is not trusted or does not match the host. If an HTTPS inspection proxy or antivirus re-signs "
                    + "traffic (Netskope, Zscaler, Fortinet, Kaspersky...) or the platform uses an internal CA, add that "
                    + "CA certificate with SAYTU_GIT_CA_BUNDLE (see docs/git-connections.md).", null, e);
        }
        if (e instanceof HttpTimeoutException) {
            return new GitProviderException(Kind.UNREACHABLE, "Timed out while contacting " + host + ".", null, e);
        }
        if (e instanceof ConnectException) {
            return new GitProviderException(Kind.UNREACHABLE, "Connection to " + host + " refused or unreachable "
                    + "(firewall, proxy or wrong port?).", null, e);
        }
        if (e instanceof UnknownHostException) {
            return new GitProviderException(Kind.UNREACHABLE, "Unknown host " + host + ".", null, e);
        }
        return new GitProviderException(Kind.UNREACHABLE, "Network error while contacting " + host + ": "
                + e.getClass().getSimpleName() + ".", null, e);
    }

    /**
     * Retry delay from {@code Retry-After} (seconds or HTTP date), GitHub {@code x-ratelimit-reset}
     * (epoch seconds) or GitLab / IETF {@code RateLimit-Reset} (epoch or delta seconds).
     */
    static Optional<Duration> retryAfter(Map<String, List<String>> headers, Clock clock) {
        Optional<Duration> fromRetryAfter = header(headers, "retry-after").flatMap(v -> parseDelayOrDate(v, clock));
        if (fromRetryAfter.isPresent()) {
            return fromRetryAfter;
        }
        for (String name : List.of("x-ratelimit-reset", "ratelimit-reset")) {
            Optional<Duration> d = header(headers, name).flatMap(v -> parseSecondsOrEpoch(v, clock));
            if (d.isPresent()) {
                return d;
            }
        }
        return Optional.empty();
    }

    private static Optional<Duration> parseDelayOrDate(String value, Clock clock) {
        Optional<Duration> seconds = parseSecondsOrEpoch(value, clock);
        if (seconds.isPresent()) {
            return seconds;
        }
        try {
            Instant at = ZonedDateTime.parse(value.strip(), DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            return Optional.of(clamp(Duration.between(clock.instant(), at)));
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }
    }

    private static Optional<Duration> parseSecondsOrEpoch(String value, Clock clock) {
        try {
            long n = Long.parseLong(value.strip());
            if (n >= EPOCH_THRESHOLD) {
                return Optional.of(clamp(Duration.between(clock.instant(), Instant.ofEpochSecond(n))));
            }
            return Optional.of(clamp(Duration.ofSeconds(n)));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private static Duration clamp(Duration d) {
        if (d.isNegative()) {
            return Duration.ZERO;
        }
        return d.compareTo(MAX_RETRY_AFTER) > 0 ? MAX_RETRY_AFTER : d;
    }

    private static GitProviderException rateLimited(String host, Optional<Duration> retryAfter, String providerMessage) {
        String when = retryAfter.map(d -> " Retry in " + Math.max(1, d.toSeconds()) + " s.").orElse("");
        return new GitProviderException(Kind.RATE_LIMITED, host + " rate limit reached." + when + providerMessage,
                retryAfter.orElse(null), null);
    }

    /** {@code message} (GitHub, GitLab, Bitbucket DC errors[0].message, Bitbucket Cloud error.message). */
    static Optional<String> providerMessage(JsonNode body) {
        if (body == null || !body.isObject()) {
            return Optional.empty();
        }
        String m = firstNonBlank(
                body.get("message").asText(),
                body.get("error").get("message").asText(),
                body.get("errors").get(0).get("message").asText(),
                body.get("error_description").asText(),
                body.get("error").asText());
        if (m == null) {
            return Optional.empty();
        }
        String clean = SecretRedactor.redact(m.replaceAll("[\\r\\n\\t]+", " ").strip());
        return Optional.of(clean.length() > MAX_PROVIDER_MESSAGE ? clean.substring(0, MAX_PROVIDER_MESSAGE) + "…" : clean);
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    static Optional<String> header(Map<String, List<String>> headers, String name) {
        if (headers == null) {
            return Optional.empty();
        }
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals(name)
                    && e.getValue() != null && !e.getValue().isEmpty()) {
                return Optional.ofNullable(e.getValue().getFirst());
            }
        }
        return Optional.empty();
    }

    private static String hostOf(String location) {
        try {
            URI u = URI.create(location.strip());
            return u.getHost() != null ? u.getScheme() + "://" + u.getHost() : "a relative path";
        } catch (IllegalArgumentException e) {
            return "an invalid location";
        }
    }
}
