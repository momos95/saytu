package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.core.git.GitProviderException.Kind;
import com.africodeshield.git.http.Auth;
import com.africodeshield.git.http.GitHttpClient;

import java.net.URI;
import java.util.List;

/**
 * Bitbucket Data Center / Server, REST API 1.0.
 * <p>
 * HTTP access tokens (personal, project or repository) are sent as {@code Authorization: Bearer};
 * if a username is set, HTTP Basic is used instead (token as password). Read permission on projects
 * and repositories is enough.
 */
public final class BitbucketDataCenterProvider extends AbstractHttpGitProvider {

    public BitbucketDataCenterProvider(GitHttpClient http) {
        super(http);
    }

    @Override
    public GitProviderType type() {
        return GitProviderType.BITBUCKET_DATA_CENTER;
    }

    static Auth auth(GitConnectionSpec spec) {
        return anonymousOr(spec, () -> spec.username() != null && !spec.username().isBlank()
                ? Auth.basic(spec.username().strip(), spec.token())
                : Auth.bearer(spec.token()));
    }

    @Override
    protected ConnectionTestResult doTest(GitConnectionSpec spec, URI api, List<String> warnings) {
        Auth auth = auth(spec);
        var properties = http.getOk(ProviderEndpoints.append(api, "/application-properties"), auth).body();
        String version = properties.text("version").orElseThrow(() -> new GitProviderException(Kind.UNEXPECTED_RESPONSE,
                "No version in /application-properties: is this a Bitbucket Data Center instance?"));
        String product = properties.text("displayName").orElse("Bitbucket");

        var projects = http.getOk(ProviderEndpoints.append(api, "/projects?limit=1"), auth);
        if (auth.isAnonymous()) {
            anonymousWarning(warnings);
            return ConnectionTestResult.ok(null, product + " " + version, List.of(), warnings, null);
        }
        if (projects.body().get("size").asLong(-1) == 0 && projects.body().get("isLastPage").asBoolean(false)) {
            warnings.add("The token can authenticate but sees no project: grant it read access to the projects to audit.");
        }
        String who = projects.header("x-ausername")
                .orElse(spec.username() != null && !spec.username().isBlank() ? spec.username().strip() : "access token");
        return ConnectionTestResult.ok(who, product + " " + version, List.of(), warnings, null);
    }
}
