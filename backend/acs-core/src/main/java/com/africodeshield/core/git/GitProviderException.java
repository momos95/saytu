package com.africodeshield.core.git;

import java.time.Duration;
import java.util.Optional;

/** Typed error raised by {@link GitProvider} implementations. Messages must never contain secrets. */
public class GitProviderException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public enum Kind {
        /** 401: token missing, invalid, expired or revoked. */
        AUTHENTICATION_FAILED(false),
        /** 403 without rate-limit headers: token lacks a scope or the user lacks a permission. */
        INSUFFICIENT_PERMISSIONS(false),
        /** 429, or 403 with rate-limit headers (GitHub). Retry after {@link #retryAfter()}. */
        RATE_LIMITED(true),
        NOT_FOUND(false),
        /** DNS, connection refused, timeout. */
        UNREACHABLE(true),
        /** Certificate validation failure. */
        TLS_ERROR(false),
        /** 5xx. */
        SERVER_ERROR(true),
        /** Response could not be understood (unsupported version, unexpected payload). */
        UNEXPECTED_RESPONSE(false);

        private final boolean retryable;

        Kind(boolean retryable) {
            this.retryable = retryable;
        }

        public boolean isRetryable() {
            return retryable;
        }
    }

    private final Kind kind;
    private final Duration retryAfter;

    public GitProviderException(Kind kind, String message) {
        this(kind, message, null, null);
    }

    public GitProviderException(Kind kind, String message, Duration retryAfter, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.retryAfter = retryAfter;
    }

    public Kind kind() {
        return kind;
    }

    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }
}
