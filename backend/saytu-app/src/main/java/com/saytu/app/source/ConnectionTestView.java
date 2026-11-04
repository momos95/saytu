package com.saytu.app.source;

import com.saytu.core.git.GitProvider.ConnectionTestResult;

import java.time.Instant;
import java.util.List;

/**
 * Outcome of a connection test, as shown in the UI.
 *
 * @param status {@code OK} or the error kind ({@code AUTHENTICATION_FAILED}, {@code RATE_LIMITED}...)
 */
public record ConnectionTestView(boolean success, String status, String message, String authenticatedAs,
                                 String serverVersion, List<String> grantedScopes, List<String> warnings,
                                 Instant tokenExpiresAt, Instant testedAt) {

    static ConnectionTestView of(ConnectionTestResult r, Instant testedAt) {
        return new ConnectionTestView(r.success(), status(r),
                r.success() ? null : r.errorMessage(), r.authenticatedAs(), r.serverVersion(),
                r.grantedScopes(), r.warnings(), r.tokenExpiresAt(), testedAt);
    }

    static String status(ConnectionTestResult r) {
        return r.success() ? "OK" : r.errorKind().name();
    }
}
