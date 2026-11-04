package com.saytu.git.http;

import com.saytu.core.security.SensitiveValue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * How a request authenticates. The header value is materialised only at send time and never kept,
 * logged or returned; {@link #toString()} is masked.
 */
public sealed interface Auth {

    /** Header name and value to add, or empty for anonymous requests. */
    Optional<String[]> header();

    /** {@code true} when no credential is sent. */
    default boolean isAnonymous() {
        return header().isEmpty();
    }

    static Auth none() {
        return None.INSTANCE;
    }

    /** {@code Authorization: Bearer <token>} (GitHub, Bitbucket access tokens). */
    static Auth bearer(SensitiveValue token) {
        return new Custom("Authorization", Objects.requireNonNull(token), "Bearer ");
    }

    /** Arbitrary header carrying the raw token, e.g. GitLab's {@code PRIVATE-TOKEN}. */
    static Auth header(String name, SensitiveValue token) {
        return new Custom(name, Objects.requireNonNull(token), "");
    }

    /** HTTP Basic (Bitbucket Cloud API tokens: Atlassian e-mail + token). */
    static Auth basic(String username, SensitiveValue password) {
        if (username == null || username.isBlank() || username.contains(":")) {
            throw new IllegalArgumentException("Basic auth requires a username without ':'");
        }
        return new Basic(username, Objects.requireNonNull(password));
    }

    final class None implements Auth {
        private static final None INSTANCE = new None();

        private None() {
        }

        @Override
        public Optional<String[]> header() {
            return Optional.empty();
        }

        @Override
        public String toString() {
            return "Auth[none]";
        }
    }

    final class Custom implements Auth {
        private final String name;
        private final SensitiveValue token;
        private final String prefix;

        private Custom(String name, SensitiveValue token, String prefix) {
            this.name = name;
            this.token = token;
            this.prefix = prefix;
        }

        @Override
        public Optional<String[]> header() {
            return Optional.of(new String[]{name, prefix + token.reveal()});
        }

        @Override
        public String toString() {
            return "Auth[" + name + ": " + prefix + SensitiveValue.MASK + "]";
        }
    }

    final class Basic implements Auth {
        private final String username;
        private final SensitiveValue password;

        private Basic(String username, SensitiveValue password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public Optional<String[]> header() {
            String raw = username + ":" + password.reveal();
            return Optional.of(new String[]{"Authorization",
                    "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8))});
        }

        @Override
        public String toString() {
            return "Auth[basic " + username + ":" + SensitiveValue.MASK + "]";
        }
    }
}
