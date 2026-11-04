package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.domain.NamespaceKind;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProviderException;
import com.saytu.core.git.GitProviderException.Kind;
import com.saytu.git.http.Auth;
import com.saytu.git.http.GitHttpClient;
import com.saytu.git.http.HttpErrorClassifier;
import com.saytu.git.json.JsonNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Bitbucket Data Center / Server, REST API 1.0.
 * <p>
 * HTTP access tokens (personal, project or repository) are sent as {@code Authorization: Bearer};
 * if a username is set, HTTP Basic is used instead (token as password). Read permission on projects
 * and repositories is enough.
 * <p>
 * Namespaces are projects (id = project key); repository ids are {@code KEY/slug}. Pagination uses
 * {@code start}/{@code limit}; the cursor is the {@code nextPageStart} offset.
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

    // ------------------------------------------------------------------ connection test

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

    // ------------------------------------------------------------------ discovery

    @Override
    public Page<Namespace> listNamespaces(GitConnectionSpec spec, PageRequest request) {
        URI api = api(spec);
        var r = http.getOk(ProviderEndpoints.append(api, "/projects?limit=" + request.size() + "&start=" + offset(request)),
                auth(spec));
        List<Namespace> items = new ArrayList<>();
        for (JsonNode p : r.body().get("values").elements()) {
            items.add(project(p));
        }
        return new Page<>(items, nextStart(r.body()), null);
    }

    @Override
    public Optional<Namespace> findNamespace(GitConnectionSpec spec, String path) {
        URI api = api(spec);
        String key = path.strip().replaceAll("^/+|/+$", "");
        if (key.isEmpty() || key.contains("/")) {
            return Optional.empty();
        }
        var r = http.get(ProviderEndpoints.append(api, "/projects/" + enc(key)), auth(spec));
        if (r.status() == 404) {
            return Optional.empty();
        }
        if (!r.isSuccess()) {
            throw HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), api, clock);
        }
        return Optional.of(project(r.body()));
    }

    @Override
    public Page<RemoteRepository> listRepositories(GitConnectionSpec spec, String namespaceExternalId, PageRequest request) {
        URI api = api(spec);
        var r = http.getOk(ProviderEndpoints.append(api, "/projects/" + enc(namespaceExternalId) + "/repos?limit="
                + request.size() + "&start=" + offset(request)), auth(spec));
        List<RemoteRepository> items = new ArrayList<>();
        for (JsonNode repo : r.body().get("values").elements()) {
            URI clone = null;
            for (JsonNode link : repo.get("links").get("clone").elements()) {
                String name = link.get("name").asText();
                if ("http".equals(name) || "https".equals(name)) {
                    clone = cleanCloneUrl(link.get("href").asText());
                }
            }
            if (clone == null) {
                continue;
            }
            String key = repo.get("project").text("key").orElse(namespaceExternalId);
            String slug = repo.get("slug").asText();
            items.add(new RemoteRepository(
                    key + "/" + slug,
                    namespaceExternalId,
                    key + "/" + slug,
                    repo.text("name").orElse(slug),
                    clone,
                    uriOrNull(repo.get("links").get("self").get(0).get("href").asText()),
                    null, // not part of the listing; known once branches are listed (isDefault)
                    repo.get("public").asBoolean(false) ? Visibility.PUBLIC : Visibility.PRIVATE,
                    repo.get("archived").asBoolean(false),
                    null));
        }
        return new Page<>(items, nextStart(r.body()), null);
    }

    @Override
    public Page<RemoteBranch> listBranches(GitConnectionSpec spec, String repositoryExternalId, PageRequest request) {
        URI api = api(spec);
        var r = http.getOk(ProviderEndpoints.append(api, repoPath(repositoryExternalId) + "/branches?limit="
                + request.size() + "&start=" + offset(request)), auth(spec));
        List<RemoteBranch> items = new ArrayList<>();
        for (JsonNode b : r.body().get("values").elements()) {
            items.add(new RemoteBranch(b.get("displayId").asText(), b.get("latestCommit").asText(),
                    b.get("isDefault").asBoolean(false), false));
        }
        return new Page<>(items, nextStart(r.body()), null);
    }

    @Override
    public Optional<String> resolveHeadCommit(GitConnectionSpec spec, String repositoryExternalId, String branch) {
        URI api = api(spec);
        var r = http.getOk(ProviderEndpoints.append(api, repoPath(repositoryExternalId) + "/branches?limit=100&filterText="
                + enc(branch)), auth(spec));
        for (JsonNode b : r.body().get("values").elements()) {
            if (branch.equals(b.get("displayId").asText())) {
                return Optional.ofNullable(b.get("latestCommit").asText());
            }
        }
        return Optional.empty();
    }

    private static String repoPath(String repositoryExternalId) {
        int slash = repositoryExternalId.indexOf('/');
        if (slash <= 0 || slash == repositoryExternalId.length() - 1 || repositoryExternalId.indexOf('/', slash + 1) >= 0) {
            throw new IllegalArgumentException("Bitbucket Data Center repository id must be KEY/slug");
        }
        return "/projects/" + enc(repositoryExternalId.substring(0, slash)) + "/repos/"
                + enc(repositoryExternalId.substring(slash + 1));
    }

    private static Namespace project(JsonNode p) {
        String key = p.get("key").asText();
        return new Namespace(key, NamespaceKind.PROJECT, key, p.text("name").orElse(key), null,
                uriOrNull(p.get("links").get("self").get(0).get("href").asText()));
    }

    private static String nextStart(JsonNode body) {
        if (body.get("isLastPage").asBoolean(true)) {
            return null;
        }
        long next = body.get("nextPageStart").asLong(-1);
        return next < 0 ? null : String.valueOf(next);
    }
}
