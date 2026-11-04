package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.core.git.GitProviderException.Kind;
import com.africodeshield.git.http.Auth;
import com.africodeshield.git.http.GitHttpClient;
import com.africodeshield.git.json.JsonNode;

import java.net.URI;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * gitlab.com and GitLab Self-Managed, REST API v4.
 * <p>
 * Authentication: personal, group or project access token in the {@code PRIVATE-TOKEN} header.
 * Required scopes: {@code read_api} (discovery) and {@code read_repository} (clone), or {@code api}.
 */
public final class GitLabProvider extends AbstractHttpGitProvider {

    static final String TOKEN_HEADER = "PRIVATE-TOKEN";

    public GitLabProvider(GitHttpClient http) {
        super(http);
    }

    @Override
    public GitProviderType type() {
        return GitProviderType.GITLAB;
    }

    static Auth auth(GitConnectionSpec spec) {
        return anonymousOr(spec, () -> Auth.header(TOKEN_HEADER, spec.token()));
    }

    @Override
    protected ConnectionTestResult doTest(GitConnectionSpec spec, URI api, List<String> warnings) {
        Auth auth = auth(spec);
        if (auth.isAnonymous()) {
            http.getOk(ProviderEndpoints.append(api, "/projects?per_page=1&simple=true&visibility=public"), auth);
            anonymousWarning(warnings);
            return ConnectionTestResult.ok(null, null, List.of(), warnings, null);
        }

        JsonNode user = http.getOk(ProviderEndpoints.append(api, "/user"), auth).body();
        String username = user.text("username").orElseThrow(() -> new GitProviderException(Kind.UNEXPECTED_RESPONSE,
                "GitLab /user response has no username: is this a GitLab instance?"));
        if (user.get("bot").asBoolean(false)) {
            warnings.add("Group or project access token (bot user " + username + "): only that group or project is visible.");
        }

        String version = null;
        var versionResponse = http.get(ProviderEndpoints.append(api, "/version"), auth);
        if (versionResponse.isSuccess()) {
            version = versionResponse.body().text("version").orElse(null);
        }

        List<String> scopes = List.of();
        Instant expiresAt = null;
        var self = http.get(ProviderEndpoints.append(api, "/personal_access_tokens/self"), auth);
        if (self.isSuccess()) {
            scopes = self.body().get("scopes").textElements();
            expiresAt = parseDate(self.body().get("expires_at").asText());
            if (!self.body().get("active").asBoolean(true) || self.body().get("revoked").asBoolean(false)) {
                throw new GitProviderException(Kind.AUTHENTICATION_FAILED, "GitLab reports this token as revoked or inactive.");
            }
            List<String> missing = missingScopes(scopes);
            if (!missing.isEmpty()) {
                throw new GitProviderException(Kind.INSUFFICIENT_PERMISSIONS, "GitLab token is missing scope(s) "
                        + String.join(", ", missing) + " (granted: " + (scopes.isEmpty() ? "none" : String.join(", ", scopes))
                        + "). Create a token with read_api and read_repository.");
            }
            if (scopes.contains("api") || scopes.contains("write_repository")) {
                warnings.add("Token grants write access (" + (scopes.contains("api") ? "api" : "write_repository")
                        + "); a read-only token with read_api and read_repository is enough.");
            }
        } else {
            warnings.add("Token scopes could not be verified (GitLab older than 15.5 or OAuth token): make sure it has "
                    + "read_api and read_repository.");
        }
        expiryWarning(expiresAt, warnings);
        return ConnectionTestResult.ok(username, version, scopes, warnings, expiresAt);
    }

    static List<String> missingScopes(List<String> scopes) {
        if (scopes.contains("api")) {
            return List.of();
        }
        List<String> missing = new ArrayList<>();
        if (!scopes.contains("read_api")) {
            missing.add("read_api");
        }
        if (!scopes.contains("read_repository") && !scopes.contains("write_repository")) {
            missing.add("read_repository");
        }
        return missing;
    }

    /** GitLab returns {@code expires_at} as a date ("2026-12-01"); the token is valid through that day (UTC). */
    static Instant parseDate(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDate.parse(value.length() > 10 ? value.substring(0, 10) : value)
                    .plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
