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
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * github.com (API at api.github.com) and GitHub Enterprise Server (API at {@code <base>/api/v3}).
 * <p>
 * Classic tokens report their scopes in {@code X-OAuth-Scopes}; fine-grained tokens and GitHub App
 * tokens do not, so their permissions can only be described, not verified.
 * <p>
 * Namespaces: the token owner ({@code user:<login>}) then the organisations they belong to.
 * Repository ids are {@code owner/name}. Pagination: {@code page} parameter, next page detected from
 * the {@code Link} header (its URL is never followed as such).
 */
public final class GitHubProvider extends AbstractHttpGitProvider {

    static final String USER_PREFIX = "user:";
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

    // ------------------------------------------------------------------ connection test

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

    // ------------------------------------------------------------------ discovery

    @Override
    public Page<Namespace> listNamespaces(GitConnectionSpec spec, PageRequest request) {
        URI api = api(spec);
        Auth auth = auth(spec);
        if (auth.isAnonymous()) {
            return new Page<>(List.of(), null, 0);
        }
        int page = page(request);
        List<Namespace> items = new ArrayList<>();
        if (page == 1) {
            String login = currentLogin(api, auth);
            items.add(new Namespace(USER_PREFIX + login, NamespaceKind.USER, login, login, null, webUrl(spec, login)));
        }
        var r = http.getOk(ProviderEndpoints.append(api, "/user/orgs?per_page=" + request.size() + "&page=" + page), auth);
        for (JsonNode org : r.body().elements()) {
            String login = org.get("login").asText();
            items.add(new Namespace(login, NamespaceKind.ORGANIZATION, login, login, null, webUrl(spec, login)));
        }
        return new Page<>(items, nextPage(page, hasNext(r)), null);
    }

    @Override
    public Optional<Namespace> findNamespace(GitConnectionSpec spec, String path) {
        URI api = api(spec);
        Auth auth = auth(spec);
        String name = path.strip().replaceAll("^/+|/+$", "");
        if (name.isEmpty() || name.contains("/")) {
            return Optional.empty();
        }
        var r = http.get(ProviderEndpoints.append(api, "/users/" + enc(name)), auth);
        if (r.status() == 404) {
            return Optional.empty();
        }
        if (!r.isSuccess()) {
            throw HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), api, clock);
        }
        String login = r.body().get("login").asText();
        boolean org = "Organization".equals(r.body().get("type").asText());
        String webUrl = r.body().get("html_url").asText();
        return Optional.of(new Namespace(org ? login : USER_PREFIX + login,
                org ? NamespaceKind.ORGANIZATION : NamespaceKind.USER, login,
                r.body().text("name").orElse(login), null, webUrl != null ? uriOrNull(webUrl) : webUrl(spec, login)));
    }

    @Override
    public Page<RemoteRepository> listRepositories(GitConnectionSpec spec, String namespaceExternalId, PageRequest request) {
        URI api = api(spec);
        Auth auth = auth(spec);
        int page = page(request);
        String query = "per_page=" + request.size() + "&page=" + page + "&sort=full_name";
        String path;
        if (namespaceExternalId.startsWith(USER_PREFIX)) {
            String login = namespaceExternalId.substring(USER_PREFIX.length());
            // The owner's private repositories are only listed by /user/repos.
            path = !auth.isAnonymous() && login.equalsIgnoreCase(currentLogin(api, auth))
                    ? "/user/repos?affiliation=owner&" + query
                    : "/users/" + enc(login) + "/repos?type=owner&" + query;
        } else {
            path = "/orgs/" + enc(namespaceExternalId) + "/repos?type=all&" + query;
        }
        var r = http.getOk(ProviderEndpoints.append(api, path), auth);
        List<RemoteRepository> items = new ArrayList<>();
        for (JsonNode repo : r.body().elements()) {
            URI clone = cleanCloneUrl(repo.get("clone_url").asText());
            if (clone == null) {
                continue;
            }
            items.add(new RemoteRepository(
                    repo.get("full_name").asText(),
                    namespaceExternalId,
                    repo.get("full_name").asText(),
                    repo.get("name").asText(),
                    clone,
                    uriOrNull(repo.get("html_url").asText()),
                    repo.text("default_branch").orElse(null),
                    visibility(repo),
                    repo.get("archived").asBoolean(false),
                    instant(repo.text("pushed_at").orElse(repo.get("updated_at").asText()))));
        }
        return new Page<>(items, nextPage(page, hasNext(r)), null);
    }

    @Override
    public Page<RemoteBranch> listBranches(GitConnectionSpec spec, String repositoryExternalId, PageRequest request) {
        URI api = api(spec);
        int page = page(request);
        var r = http.getOk(ProviderEndpoints.append(api, "/repos/" + encPath(repositoryExternalId)
                + "/branches?per_page=" + request.size() + "&page=" + page), auth(spec));
        List<RemoteBranch> items = new ArrayList<>();
        for (JsonNode b : r.body().elements()) {
            items.add(new RemoteBranch(b.get("name").asText(), b.get("commit").get("sha").asText(), false,
                    b.get("protected").asBoolean(false)));
        }
        return new Page<>(items, nextPage(page, hasNext(r)), null);
    }

    @Override
    public Optional<String> resolveHeadCommit(GitConnectionSpec spec, String repositoryExternalId, String branch) {
        URI api = api(spec);
        var r = http.get(ProviderEndpoints.append(api, "/repos/" + encPath(repositoryExternalId) + "/branches/"
                + enc(branch)), auth(spec));
        if (r.status() == 404) {
            return Optional.empty();
        }
        if (!r.isSuccess()) {
            throw HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), api, clock);
        }
        return r.body().get("commit").text("sha");
    }

    // ------------------------------------------------------------------ helpers

    private String currentLogin(URI api, Auth auth) {
        return http.getOk(ProviderEndpoints.append(api, "/user"), auth).body().text("login")
                .orElseThrow(() -> new GitProviderException(Kind.UNEXPECTED_RESPONSE, "GitHub /user has no login"));
    }

    /** {@code Link: <...&page=3>; rel="next", <...>; rel="last"} */
    static boolean hasNext(GitHttpClient.Response r) {
        return r.header("link").map(l -> l.matches("(?s).*rel=\"?next\"?.*")).orElse(false);
    }

    private static URI webUrl(GitConnectionSpec spec, String login) {
        String host = spec.baseUrl().getHost();
        String base = host != null && host.equalsIgnoreCase("api.github.com") ? "https://github.com" : spec.baseUrl().toString();
        return URI.create(base.replaceAll("/+$", "") + "/" + enc(login));
    }

    static Visibility visibility(JsonNode repo) {
        Visibility v = GitLabProvider.visibility(repo.get("visibility").asText());
        if (v != null) {
            return v;
        }
        return repo.get("private").asBoolean(false) ? Visibility.PRIVATE : Visibility.PUBLIC;
    }

    private static String serverVersion(GitHttpClient.Response r) {
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
