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
 * bitbucket.org, REST API 2.0.
 * <p>
 * App passwords stopped working on 9 June 2026. Two credential types are supported:
 * <ul>
 *   <li>API token of a user account: username = Atlassian account e-mail, HTTP Basic;</li>
 *   <li>workspace / project / repository access token: no username, {@code Authorization: Bearer}.</li>
 * </ul>
 * Scopes needed: {@code read:user:bitbucket}, {@code read:workspace:bitbucket},
 * {@code read:repository:bitbucket}.
 */
public final class BitbucketCloudProvider extends AbstractHttpGitProvider {

    public BitbucketCloudProvider(GitHttpClient http) {
        super(http);
    }

    @Override
    public GitProviderType type() {
        return GitProviderType.BITBUCKET_CLOUD;
    }

    static Auth auth(GitConnectionSpec spec) {
        return anonymousOr(spec, () -> spec.username() != null && !spec.username().isBlank()
                ? Auth.basic(spec.username().strip(), spec.token())
                : Auth.bearer(spec.token()));
    }

    @Override
    protected ConnectionTestResult doTest(GitConnectionSpec spec, URI api, List<String> warnings) {
        Auth auth = auth(spec);
        if (auth.isAnonymous()) {
            http.getOk(ProviderEndpoints.append(api, "/repositories?pagelen=1"), auth);
            anonymousWarning(warnings);
            return ConnectionTestResult.ok(null, "bitbucket.org", List.of(), warnings, null);
        }
        boolean bearer = spec.username() == null || spec.username().isBlank();
        var user = http.get(ProviderEndpoints.append(api, "/user"), auth);
        List<String> scopes = user.header("x-oauth-scopes").map(GitHubProvider::splitScopes).orElse(List.of());
        if (user.isSuccess()) {
            String name = user.body().text("username")
                    .or(() -> user.body().text("display_name"))
                    .orElseThrow(() -> new GitProviderException(Kind.UNEXPECTED_RESPONSE,
                            "Bitbucket /user response has no username"));
            return ConnectionTestResult.ok(name, "bitbucket.org", scopes, warnings, null);
        }
        if (bearer && user.status() == 403) {
            // Access tokens belong to a workspace, project or repository, not to a user.
            http.getOk(ProviderEndpoints.append(api, "/repositories?role=member&pagelen=1"), auth);
            warnings.add("Workspace, project or repository access token: only the resources it was created for are visible.");
            return ConnectionTestResult.ok("access token", "bitbucket.org", scopes, warnings, null);
        }
        if (user.status() == 401 && !bearer) {
            throw new GitProviderException(Kind.AUTHENTICATION_FAILED, "Bitbucket rejected the credentials (401). "
                    + "Use your Atlassian account e-mail as username and an API token (app passwords no longer work).");
        }
        throw com.africodeshield.git.http.HttpErrorClassifier.fromResponse(user.status(), user.headers(), user.body(),
                ProviderEndpoints.append(api, "/user"), clock);
    }
}
