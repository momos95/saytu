package com.africodeshield.git.http;

import com.africodeshield.core.git.GitProviderException.Kind;
import com.africodeshield.git.json.JsonNode;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLHandshakeException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpErrorClassifierTest {

    private static final Instant NOW = Instant.parse("2026-11-04T10:00:00Z");
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final URI uri = URI.create("https://gitlab.example.org/api/v4/user");

    private Kind kind(int status, Map<String, List<String>> headers) {
        return HttpErrorClassifier.fromResponse(status, headers, JsonNode.MISSING, uri, clock).kind();
    }

    @Test
    void mapsStatuses() {
        assertEquals(Kind.AUTHENTICATION_FAILED, kind(401, Map.of()));
        assertEquals(Kind.INSUFFICIENT_PERMISSIONS, kind(403, Map.of()));
        assertEquals(Kind.NOT_FOUND, kind(404, Map.of()));
        assertEquals(Kind.RATE_LIMITED, kind(429, Map.of()));
        assertEquals(Kind.SERVER_ERROR, kind(502, Map.of()));
        assertEquals(Kind.UNEXPECTED_RESPONSE, kind(418, Map.of()));
        assertEquals(Kind.UNEXPECTED_RESPONSE, kind(301, Map.of("Location", List.of("https://evil.example/x?token=1"))));
    }

    @Test
    void redirectMessageNamesHostOnly() {
        var e = HttpErrorClassifier.fromResponse(302, Map.of("location", List.of("https://login.example.org/sso?ticket=abc")),
                JsonNode.MISSING, uri, clock);
        assertTrue(e.getMessage().contains("https://login.example.org"));
        assertFalse(e.getMessage().contains("ticket"));
    }

    @Test
    void githubPrimaryRateLimitIs403WithZeroRemaining() {
        var e = HttpErrorClassifier.fromResponse(403, Map.of(
                "x-ratelimit-remaining", List.of("0"),
                "x-ratelimit-reset", List.of(String.valueOf(NOW.getEpochSecond() + 120))), JsonNode.MISSING, uri, clock);
        assertEquals(Kind.RATE_LIMITED, e.kind());
        assertEquals(Optional.of(Duration.ofSeconds(120)), e.retryAfter());
    }

    @Test
    void retryAfterFormats() {
        assertEquals(Optional.of(Duration.ofSeconds(30)),
                HttpErrorClassifier.retryAfter(Map.of("Retry-After", List.of("30")), clock));
        assertEquals(Optional.of(Duration.ofSeconds(90)),
                HttpErrorClassifier.retryAfter(Map.of("Retry-After", List.of("Wed, 04 Nov 2026 10:01:30 GMT")), clock));
        assertEquals(Optional.of(Duration.ofSeconds(60)),
                HttpErrorClassifier.retryAfter(Map.of("RateLimit-Reset", List.of(String.valueOf(NOW.getEpochSecond() + 60))), clock));
        assertEquals(Optional.of(Duration.ZERO),
                HttpErrorClassifier.retryAfter(Map.of("x-ratelimit-reset", List.of(String.valueOf(NOW.getEpochSecond() - 5))), clock));
        assertEquals(Optional.of(Duration.ofHours(24)),
                HttpErrorClassifier.retryAfter(Map.of("Retry-After", List.of("999999")), clock));
        assertEquals(Optional.empty(), HttpErrorClassifier.retryAfter(Map.of("Retry-After", List.of("soon")), clock));
    }

    @Test
    void providerMessagesAreExtractedRedactedAndTruncated() {
        assertEquals(Optional.of("403 Forbidden"),
                HttpErrorClassifier.providerMessage(JsonNode.parse("{\"message\":\"403 Forbidden\"}")));
        assertEquals(Optional.of("Bad scope"),
                HttpErrorClassifier.providerMessage(JsonNode.parse("{\"errors\":[{\"message\":\"Bad scope\"}]}")));
        assertEquals(Optional.of("nope"),
                HttpErrorClassifier.providerMessage(JsonNode.parse("{\"type\":\"error\",\"error\":{\"message\":\"nope\"}}")));
        String echoed = HttpErrorClassifier.providerMessage(
                JsonNode.parse("{\"message\":\"token glpat-abcdefghijklmnopqrstuv invalid\"}")).orElseThrow();
        assertFalse(echoed.contains("glpat-abcdefghij"));
        String longMsg = HttpErrorClassifier.providerMessage(
                JsonNode.parse("{\"message\":\"" + "x".repeat(500) + "\"}")).orElseThrow();
        assertEquals(201, longMsg.length());
    }

    @Test
    void ioExceptionsAreTyped() {
        assertEquals(Kind.TLS_ERROR, HttpErrorClassifier.fromIOException(new SSLHandshakeException("PKIX"), uri).kind());
        String tls = HttpErrorClassifier.fromIOException(new SSLHandshakeException("PKIX"), uri).getMessage();
        assertTrue(tls.contains("ACS_GIT_CA_BUNDLE"));
        assertTrue(tls.contains("inspection proxy"));
        assertEquals(Kind.UNREACHABLE, HttpErrorClassifier.fromIOException(new HttpTimeoutException("t"), uri).kind());
        assertEquals(Kind.UNREACHABLE, HttpErrorClassifier.fromIOException(new ConnectException("c"), uri).kind());
        assertTrue(Kind.UNREACHABLE.isRetryable());
        assertFalse(Kind.BLOCKED_BY_POLICY.isRetryable());
    }
}
