package com.saytu.scan.git;

/** Clone failure. Messages are safe to store and display: they never contain credentials. */
public final class CheckoutException extends Exception {

    private static final long serialVersionUID = 1L;

    public enum Kind {
        AUTHENTICATION_FAILED,
        /** Repository missing or not visible to the credentials. */
        NOT_FOUND,
        BRANCH_NOT_FOUND,
        UNREACHABLE,
        TLS_ERROR,
        TIMEOUT,
        /** Checkout larger than the configured quota. */
        TOO_LARGE,
        /** URL refused by policy (scheme, embedded credentials, path outside the local root...). */
        BLOCKED_BY_POLICY,
        FAILED
    }

    private final Kind kind;

    public CheckoutException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
