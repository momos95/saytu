package com.saytu.app.source;

import com.saytu.core.domain.GitProviderType;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Read model of a connection. Exposes whether a token exists, never the token. */
public record GitConnectionView(
        UUID id,
        String name,
        GitProviderType providerType,
        String baseUrl,
        String apiUrl,
        String username,
        boolean hasToken,
        boolean enabled,
        LastTest lastTest,
        Instant tokenExpiresAt,
        String createdBy,
        Instant createdAt,
        Instant updatedAt,
        long version) {

    public record LastTest(String status, String message, String authenticatedAs, String serverVersion,
                           List<String> warnings, Instant testedAt) {
    }

    static GitConnectionView of(GitConnectionEntity e) {
        LastTest last = e.getLastTestedAt() == null ? null : new LastTest(e.getLastTestStatus(), e.getLastTestMessage(),
                e.getLastTestIdentity(), e.getLastTestServerVersion(), e.getLastTestWarnings(), e.getLastTestedAt());
        return new GitConnectionView(e.getId(), e.getName(), e.getProviderType(), e.getBaseUrl(), e.getApiUrl(),
                e.getUsername(), e.hasToken(), e.isEnabled(), last, e.getTokenExpiresAt(), e.getCreatedBy(),
                e.getCreatedAt(), e.getUpdatedAt(), e.getVersion());
    }
}
