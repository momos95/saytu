package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.domain.NamespaceKind;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.core.git.GitProviderException.Kind;
import com.africodeshield.git.http.Auth;
import com.africodeshield.git.http.GitHttpClient;
import com.africodeshield.git.http.HttpErrorClassifier;
import com.africodeshield.git.json.JsonNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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
 * <p>
 * Cross-workspace endpoints were removed by Atlassian (CHANGE-2770): workspaces come from
 * {@code /user/workspaces}, repositories from {@code /repositories/{workspace}}. Access tokens are not
 * users: their workspace must be added by name ({@link #findNamespace}).
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
        return anonymousOr(spec, () -> isBearer(spec)
                ? Auth.bearer(spec.token())
                : Auth.basic(spec.username().strip(), spec.token()));
    }

    private static boolean isBearer(GitConnectionSpec spec) {
        return spec.username() == null || spec.username().isBlank();
    }

    // ------------------------------------------------------------------ connection test

    @Override
    protected ConnectionTestResult doTest(GitConnectionSpec spec, URI api, List<String> warnings) {
        Auth auth = auth(spec);
        if (auth.isAnonymous()) {
            // Reachability only: an anonymous /user call is expected to answer 401 from the real API.
            var probe = http.get(ProviderEndpoints.append(api, "/user"), auth);
            if (!probe.isSuccess() && probe.status() != 401) {
                throw HttpErrorClassifier.fromResponse(probe.status(), probe.headers(), probe.body(), api, clock);
            }
            anonymousWarning(warnings);
            warnings.add("Add public workspaces by name in 'Organisations & dépôts'.");
            return ConnectionTestResult.ok(null, "bitbucket.org", List.of(), warnings, null);
        }
        boolean bearer = isBearer(spec);
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
            // Accepted credentials that do not belong to a user: workspace, project or repository access token.
            warnings.add("Workspace, project or repository access token: add its workspace by name in "
                    + "'Organisations & dépôts'; only the resources it was created for are visible.");
            return ConnectionTestResult.ok("access token", "bitbucket.org", scopes, warnings, null);
        }
        if (user.status() == 401 && !bearer) {
            throw new GitProviderException(Kind.AUTHENTICATION_FAILED, "Bitbucket rejected the credentials (401). "
                    + "Use your Atlassian account e-mail as username and an API token (app passwords no longer work).");
        }
        throw HttpErrorClassifier.fromResponse(user.status(), user.headers(), user.body(),
                ProviderEndpoints.append(api, "/user"), clock);
    }

    // ------------------------------------------------------------------ discovery

    @Override
    public Page<Namespace> listNamespaces(GitConnectionSpec spec, PageRequest request) {
        URI api = api(spec);
        Auth auth = auth(spec);
        if (auth.isAnonymous()) {
            return new Page<>(List.of(), null, 0);
        }
        int page = page(request);
        var r = http.get(ProviderEndpoints.append(api, "/user/workspaces?pagelen=" + request.size() + "&page=" + page), auth);
        if (!r.isSuccess()) {
            if (isBearer(spec) && (r.status() == 403 || r.status() == 401)) {
                return new Page<>(List.of(), null, 0); // access token: workspaces are added by name
            }
            throw HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), api, clock);
        }
        List<Namespace> items = new ArrayList<>();
        for (JsonNode v : r.body().get("values").elements()) {
            // Entries wrap the workspace ({"workspace": {...}}); accept a bare workspace as well.
            JsonNode ws = v.get("workspace").isObject() ? v.get("workspace") : v;
            String slug = ws.get("slug").asText();
            if (slug == null) {
                continue;
            }
            items.add(workspace(slug, ws.text("name").orElse(slug), ws.get("links").get("html").get("href").asText()));
        }
        return new Page<>(items, nextPage(page, !r.body().get("next").isAbsent()), size(r.body()));
    }

    @Override
    public Optional<Namespace> findNamespace(GitConnectionSpec spec, String path) {
        URI api = api(spec);
        String slug = path.strip().replaceAll("^/+|/+$", "");
        if (slug.isEmpty() || slug.contains("/")) {
            return Optional.empty();
        }
        // Listing one repository proves the workspace exists and is visible, including for access tokens.
        var r = http.get(ProviderEndpoints.append(api, "/repositories/" + enc(slug) + "?pagelen=1"), auth(spec));
        if (r.status() == 404) {
            return Optional.empty();
        }
        if (!r.isSuccess()) {
            throw HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), api, clock);
        }
        return Optional.of(workspace(slug, slug, null));
    }

    @Override
    public Page<RemoteRepository> listRepositories(GitConnectionSpec spec, String namespaceExternalId, PageRequest request) {
        URI api = api(spec);
        int page = page(request);
        var r = http.getOk(ProviderEndpoints.append(api, "/repositories/" + enc(namespaceExternalId)
                + "?pagelen=" + request.size() + "&page=" + page + "&sort=full_name"), auth(spec));
        List<RemoteRepository> items = new ArrayList<>();
        for (JsonNode repo : r.body().get("values").elements()) {
            URI clone = null;
            for (JsonNode link : repo.get("links").get("clone").elements()) {
                if ("https".equals(link.get("name").asText())) {
                    clone = cleanCloneUrl(link.get("href").asText());
                }
            }
            if (clone == null) {
                continue;
            }
            items.add(new RemoteRepository(
                    repo.get("full_name").asText(),
                    namespaceExternalId,
                    repo.get("full_name").asText(),
                    repo.text("name").orElse(repo.get("slug").asText()),
                    clone,
                    uriOrNull(repo.get("links").get("html").get("href").asText()),
                    repo.get("mainbranch").text("name").orElse(null),
                    repo.get("is_private").asBoolean(true) ? Visibility.PRIVATE : Visibility.PUBLIC,
                    false,
                    instant(repo.get("updated_on").asText())));
        }
        return new Page<>(items, nextPage(page, !r.body().get("next").isAbsent()), size(r.body()));
    }

    @Override
    public Page<RemoteBranch> listBranches(GitConnectionSpec spec, String repositoryExternalId, PageRequest request) {
        URI api = api(spec);
        int page = page(request);
        var r = http.getOk(ProviderEndpoints.append(api, "/repositories/" + encPath(repositoryExternalId)
                + "/refs/branches?pagelen=" + request.size() + "&page=" + page), auth(spec));
        List<RemoteBranch> items = new ArrayList<>();
        for (JsonNode b : r.body().get("values").elements()) {
            items.add(new RemoteBranch(b.get("name").asText(), b.get("target").get("hash").asText(), false, false));
        }
        return new Page<>(items, nextPage(page, !r.body().get("next").isAbsent()), size(r.body()));
    }

    @Override
    public Optional<String> resolveHeadCommit(GitConnectionSpec spec, String repositoryExternalId, String branch) {
        URI api = api(spec);
        var r = http.get(ProviderEndpoints.append(api, "/repositories/" + encPath(repositoryExternalId)
                + "/refs/branches/" + enc(branch)), auth(spec));
        if (r.status() == 404) {
            return Optional.empty();
        }
        if (!r.isSuccess()) {
            throw HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), api, clock);
        }
        return r.body().get("target").text("hash");
    }

    private static Namespace workspace(String slug, String name, String webUrl) {
        return new Namespace(slug, NamespaceKind.WORKSPACE, slug, name, null,
                webUrl != null ? uriOrNull(webUrl) : URI.create("https://bitbucket.org/" + enc(slug)));
    }

    private static Integer size(JsonNode body) {
        long size = body.get("size").asLong(-1);
        return size < 0 || size > Integer.MAX_VALUE ? null : (int) size;
    }
}
