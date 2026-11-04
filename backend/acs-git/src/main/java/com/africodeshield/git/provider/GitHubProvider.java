package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.core.git.GitProviderException.Kind;
import com.africodeshield.git.http.Auth;
import com.africodeshield.git.http.GitHttpClient;

import java.net.URI;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * github.com (API at api.github.com) and GitHub Enterprise Server (API at {@code <base>/api/v3}).
 * <p>
 * Classic tokens report their scopes in {@code X-OAuth-Scopes}; fine-grained tokens and GitHub App
 * tokens do not, so their permissions can only be described, not verified.
 */
public final class GitHubProvider extends AbstractHttpGitProvider {

    private static final DateTimeFormatter EXPIRATION_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss[ z][ XX][ XXX]");

    public GitHubProvider(GitHttpClient http) {
        super(http);
    }

    @Override
    public GitProviderType type() {
        return GitProviderType.GITHUB;
    }

    static Auth auth(GitConnectionSpec spec) {
        return anonymousOr(spec, () -> Auth.bearer(spec.token()));
    }

    @Override
    protected ConnectionTestResult doTest(GitConnectionSpec spec, URI api, List<String> warnings) {
        Auth auth = auth(spec);
        if (auth.isAnonymous()) {
            var r = http.getOk(ProviderEndpoints.append(api, "/rate_limit"), auth);
            anonymousWarning(warnings);
            return ConnectionTestResult.ok(null, serverVersion(r), List.of(), warnings, null);
        }

        var user = http.getOk(ProviderEndpoints.append(api, "/user"), auth);
        String login = user.body().text("login").orElseThrow(() -> new GitProviderException(Kind.UNEXPECTED_RESPONSE,
                "GitHub /user response has no login: is this a GitHub instance?"));

        Optional<String> scopesHeader = user.header("x-oauth-scopes");
        List<String> scopes = scopesHeader.map(GitHubProvider::splitScopes).orElse(List.of());
        if (scopesHeader.isPresent()) {
            if (!scopes.contains("repo")) {
                warnings.add("Classic token without the 'repo' scope: only public repositories can be audited.");
            } else {
                warnings.add("Classic token with 'repo' also grants write access; a fine-grained token with "
                        + "Contents: read and Metadata: read is enough.");
            }
            if (scopes.stream().noneMatch(s -> s.equals("read:org") || s.equals("write:org") || s.equals("admin:org"))) {
                warnings.add("Missing 'read:org': organisations where your membership is private will not be listed.");
            }
        } else {
            warnings.add("Fine-grained or GitHub App token: permissions cannot be checked through the API. It needs "
                    + "Contents: read and Metadata: read on the repositories to audit.");
        }

        Instant expiresAt = user.header("github-authentication-token-expiration")
                .map(GitHubProvider::parseExpiration).orElse(null);
        expiryWarning(expiresAt, warnings);
        return ConnectionTestResult.ok(login, serverVersion(user), scopes, warnings, expiresAt);
    }

    private static String serverVersion(com.africodeshield.git.http.GitHttpClient.Response r) {
        return r.header("x-github-enterprise-version").map(v -> "GitHub Enterprise Server " + v).orElse("github.com");
    }

    static List<String> splitScopes(String header) {
        if (header.isBlank()) {
            return List.of();
        }
        return Arrays.stream(header.split(",")).map(String::strip).filter(s -> !s.isEmpty()).toList();
    }

    /** Header format: {@code 2026-12-01 12:00:00 UTC} (sometimes with a numeric offset). */
    static Instant parseExpiration(String value) {
        try {
            return ZonedDateTime.parse(value.strip(), EXPIRATION_FORMAT).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
