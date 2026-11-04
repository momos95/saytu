package com.saytu.core.security;

import java.util.Arrays;
import java.util.Objects;

/**
 * Holder for a secret (Git token, webhook secret...) that can never leak through
 * {@link #toString()}, logging frameworks, exception messages or Jackson serialisation of records.
 * <p>
 * The value is kept as a {@code char[]} so it can be wiped with {@link #destroy()} once used.
 */
public final class SensitiveValue implements AutoCloseable {

    public static final String MASK = "********";

    private final char[] value;
    private volatile boolean destroyed;

    private SensitiveValue(char[] value) {
        this.value = value;
    }

    public static SensitiveValue of(String value) {
        Objects.requireNonNull(value, "value");
        return new SensitiveValue(value.toCharArray());
    }

    public static SensitiveValue of(char[] value) {
        Objects.requireNonNull(value, "value");
        return new SensitiveValue(value.clone());
    }

    /** Explicit, greppable access to the clear value. Callers must not log the result. */
    public String reveal() {
        ensureAlive();
        return new String(value);
    }

    public char[] revealChars() {
        ensureAlive();
        return value.clone();
    }

    public boolean isBlank() {
        ensureAlive();
        for (char c : value) {
            if (!Character.isWhitespace(c)) {
                return false;
            }
        }
        return true;
    }

    public int length() {
        ensureAlive();
        return value.length;
    }

    /** Overwrites the in-memory value. Further access throws {@link IllegalStateException}. */
    public void destroy() {
        Arrays.fill(value, '\0');
        destroyed = true;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public void close() {
        destroy();
    }

    private void ensureAlive() {
        if (destroyed) {
            throw new IllegalStateException("Sensitive value has been destroyed");
        }
    }

    @Override
    public String toString() {
        return MASK;
    }

    /** Identity semantics on purpose: comparing secrets by value invites timing side channels. */
    @Override
    public boolean equals(Object obj) {
        return this == obj;
    }

    @Override
    public int hashCode() {
        return System.identityHashCode(this);
    }
}
