package com.saytu.scan.git;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.security.SensitiveValue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * Credentials for one clone, turned into an HTTP {@code Authorization} header given to the git
 * process through its environment only (never on the command line, never written to {@code .git/config}).
 */
public final class GitCredentials {

    private final boolean bearer;
    private final String username;
    private final SensitiveValue secret;

    private GitCredentials(boolean bearer, String username, SensitiveValue secret) {
        this.bearer = bearer;
        this.username = username;
        this.secret = Objects.requireNonNull(secret, "secret");
    }

    public static GitCredentials basic(String username, SensitiveValue secret) {
        if (username == null || username.isBlank() || username.indexOf(':') >= 0) {
            throw new IllegalArgumentException("invalid username for HTTP basic authentication");
        }
        return new GitCredentials(false, username, secret);
    }

    public static GitCredentials bearer(SensitiveValue secret) {
        return new GitCredentials(true, null, secret);
    }

    /**
     * Git-over-HTTPS convention of each platform:
     * <ul>
     *   <li>GitLab: any user name with a personal / project / group access token ({@code oauth2});</li>
     *   <li>GitHub / GHES: {@code x-access-token} with a classic or fine-grained token;</li>
     *   <li>Bitbucket Cloud: {@code x-token-auth}, valid for API tokens and repository / project /
     *       workspace access tokens;</li>
     *   <li>Bitbucket Data Center: the account name for a personal HTTP access token, Bearer for
     *       project / repository tokens (no account name configured).</li>
     * </ul>
     */
    public static GitCredentials forProvider(GitProviderType type, String connectionUsername, SensitiveValue token) {
        return switch (type) {
            case GITLAB -> basic("oauth2", token);
            case GITHUB -> basic("x-access-token", token);
            case BITBUCKET_CLOUD -> basic("x-token-auth", token);
            case BITBUCKET_DATA_CENTER -> connectionUsername == null || connectionUsername.isBlank()
                    ? bearer(token) : basic(connectionUsername, token);
            case LOCAL -> throw new IllegalArgumentException("local repositories take no credentials");
        };
    }

    /** Value of the Authorization header. Contains the secret: only for the git process environment. */
    String authorizationHeader() {
        if (bearer) {
            return "Authorization: Bearer " + secret.reveal();
        }
        String pair = username + ":" + secret.reveal();
        return "Authorization: Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }

    /** Values to mask in any captured output. */
    java.util.List<String> sensitiveStrings() {
        String header = authorizationHeader();
        return java.util.List.of(secret.reveal(), header.substring(header.indexOf(' ', 15) + 1));
    }

    @Override
    public String toString() {
        return "GitCredentials[" + (bearer ? "bearer" : "basic " + username) + ", " + SensitiveValue.MASK + "]";
    }
}
