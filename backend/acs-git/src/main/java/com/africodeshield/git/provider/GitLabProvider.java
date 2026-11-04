package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.domain.NamespaceKind;
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
import java.util.Optional;

/**
 * gitlab.com and GitLab Self-Managed, REST API v4.
 * <p>
 * Authentication: personal, group or project access token in the {@code PRIVATE-TOKEN} header.
 * Required scopes: {@code read_api} (discovery) and {@code read_repository} (clone), or {@code api}.
 * <p>
 * Namespaces: the token owner's personal namespace ({@code user:<id>}) then every group and
 * sub-group the user is a member of. Pagination follows the {@code X-Next-Page} header.
 */
public final class GitLabProvider extends AbstractHttpGitProvider {

    static final String TOKEN_HEADER = "PRIVATE-TOKEN";
    static final String USER_PREFIX = "user:";

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

    // ------------------------------------------------------------------ connection test

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

    // ------------------------------------------------------------------ discovery

    @Override
    public Page<Namespace> listNamespaces(GitConnectionSpec spec, PageRequest request) {
        URI api = api(spec);
        Auth auth = auth(spec);
        if (auth.isAnonymous()) {
            // Without a token every public group of the instance would be listed: add groups by name instead.
            return new Page<>(List.of(), null, 0);
        }
        int page = page(request);
        List<Namespace> items = new ArrayList<>();
        if (page == 1) {
            JsonNode user = http.getOk(ProviderEndpoints.append(api, "/user"), auth).body();
            if (!user.get("bot").asBoolean(false)) {
                items.add(userNamespace(user));
            }
        }
        var r = http.getOk(ProviderEndpoints.append(api, "/groups?min_access_level=10&order_by=path&sort=asc"
                + "&per_page=" + request.size() + "&page=" + page), auth);
        for (JsonNode g : r.body().elements()) {
            items.add(groupNamespace(g));
        }
        return new Page<>(items, nextPage(r), total(r));
    }

    @Override
    public Optional<Namespace> findNamespace(GitConnectionSpec spec, String path) {
        URI api = api(spec);
        Auth auth = auth(spec);
        String clean = path.strip().replaceAll("^/+|/+$", "");
        if (clean.isEmpty()) {
            return Optional.empty();
        }
        var group = http.get(ProviderEndpoints.append(api, "/groups/" + enc(clean) + "?with_projects=false"), auth);
        if (group.isSuccess()) {
            return Optional.of(groupNamespace(group.body()));
        }
        if (group.status() != 404) {
            throw com.africodeshield.git.http.HttpErrorClassifier.fromResponse(group.status(), group.headers(),
                    group.body(), api, clock);
        }
        if (clean.contains("/")) {
            return Optional.empty();
        }
        JsonNode users = http.getOk(ProviderEndpoints.append(api, "/users?username=" + enc(clean)), auth).body();
        return users.elements().stream().findFirst().map(GitLabProvider::userNamespace);
    }

    @Override
    public Page<RemoteRepository> listRepositories(GitConnectionSpec spec, String namespaceExternalId, PageRequest request) {
        URI api = api(spec);
        Auth auth = auth(spec);
        int page = page(request);
        String base = namespaceExternalId.startsWith(USER_PREFIX)
                ? "/users/" + enc(namespaceExternalId.substring(USER_PREFIX.length())) + "/projects?"
                : "/groups/" + enc(namespaceExternalId) + "/projects?include_subgroups=false&with_shared=false&";
        var r = http.getOk(ProviderEndpoints.append(api, base + "order_by=path&sort=asc&per_page=" + request.size()
                + "&page=" + page), auth);
        List<RemoteRepository> items = new ArrayList<>();
        for (JsonNode p : r.body().elements()) {
            URI clone = cleanCloneUrl(p.get("http_url_to_repo").asText());
            if (clone == null) {
                continue;
            }
            items.add(new RemoteRepository(
                    p.get("id").asText(),
                    namespaceExternalId,
                    p.get("path_with_namespace").asText(),
                    p.text("name").orElse(p.get("path").asText()),
                    clone,
                    uriOrNull(p.get("web_url").asText()),
                    p.text("default_branch").orElse(null),
                    visibility(p.get("visibility").asText()),
                    p.get("archived").asBoolean(false),
                    instant(p.get("last_activity_at").asText())));
        }
        return new Page<>(items, nextPage(r), total(r));
    }

    @Override
    public Page<RemoteBranch> listBranches(GitConnectionSpec spec, String repositoryExternalId, PageRequest request) {
        URI api = api(spec);
        int page = page(request);
        var r = http.getOk(ProviderEndpoints.append(api, "/projects/" + enc(repositoryExternalId)
                + "/repository/branches?per_page=" + request.size() + "&page=" + page), auth(spec));
        List<RemoteBranch> items = new ArrayList<>();
        for (JsonNode b : r.body().elements()) {
            items.add(new RemoteBranch(b.get("name").asText(), b.get("commit").get("id").asText(),
                    b.get("default").asBoolean(false), b.get("protected").asBoolean(false)));
        }
        return new Page<>(items, nextPage(r), total(r));
    }

    @Override
    public Optional<String> resolveHeadCommit(GitConnectionSpec spec, String repositoryExternalId, String branch) {
        URI api = api(spec);
        var r = http.get(ProviderEndpoints.append(api, "/projects/" + enc(repositoryExternalId)
                + "/repository/branches/" + enc(branch)), auth(spec));
        if (r.status() == 404) {
            return Optional.empty();
        }
        if (!r.isSuccess()) {
            throw com.africodeshield.git.http.HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), api, clock);
        }
        return r.body().get("commit").text("id");
    }

    private static Namespace userNamespace(JsonNode user) {
        return new Namespace(USER_PREFIX + user.get("id").asText(), NamespaceKind.USER,
                user.get("username").asText(), user.text("name").orElse(user.get("username").asText()), null,
                uriOrNull(user.get("web_url").asText()));
    }

    private static Namespace groupNamespace(JsonNode g) {
        String parent = g.get("parent_id").isAbsent() ? null : g.get("parent_id").asText();
        return new Namespace(g.get("id").asText(), parent == null ? NamespaceKind.GROUP : NamespaceKind.SUBGROUP,
                g.get("full_path").asText(), g.text("name").orElse(g.get("path").asText()), parent,
                uriOrNull(g.get("web_url").asText()));
    }

    private static String nextPage(com.africodeshield.git.http.GitHttpClient.Response r) {
        return r.header("x-next-page").filter(v -> v.strip().matches("\\d{1,9}")).map(String::strip).orElse(null);
    }

    private static Integer total(com.africodeshield.git.http.GitHttpClient.Response r) {
        return r.header("x-total").filter(v -> v.strip().matches("\\d{1,9}")).map(v -> Integer.parseInt(v.strip())).orElse(null);
    }

    static Visibility visibility(String value) {
        if (value == null) {
            return null;
        }
        return switch (value) {
            case "public" -> Visibility.PUBLIC;
            case "internal" -> Visibility.INTERNAL;
            case "private" -> Visibility.PRIVATE;
            default -> null;
        };
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
