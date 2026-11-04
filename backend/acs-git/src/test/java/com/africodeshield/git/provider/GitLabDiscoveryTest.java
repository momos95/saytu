package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.domain.NamespaceKind;
import com.africodeshield.core.git.GitProvider.PageRequest;
import com.africodeshield.core.git.GitProvider.Visibility;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.git.FakeGitServer;
import com.africodeshield.git.FakeGitServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitLabDiscoveryTest {

    private FakeGitServer server;
    private GitLabProvider provider;

    @BeforeEach
    void start() throws Exception {
        server = new FakeGitServer();
        provider = new GitLabProvider(FakeGitServer.client());
        server.on("/api/v4/user", Reply.json("{\"id\":7,\"username\":\"seckma95\",\"name\":\"Mamadou Seck\",\"web_url\":\"https://gitlab.com/seckma95\"}"));
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void firstPageHasPersonalNamespaceThenGroupsAndSubgroups() {
        server.on("/api/v4/groups?min_access_level=10&order_by=path&sort=asc&per_page=2&page=1", Reply.json("""
                [{"id":10,"name":"Acme","path":"acme","full_path":"acme","parent_id":null,"web_url":"https://gitlab.com/groups/acme"},
                 {"id":11,"name":"Payments","path":"pay","full_path":"acme/pay","parent_id":10,"web_url":"https://gitlab.com/groups/acme/pay"}]""")
                .withHeader("X-Next-Page", "2").withHeader("X-Total", "3"));
        var page = provider.listNamespaces(server.spec(GitProviderType.GITLAB, "t"), PageRequest.first(2));

        assertEquals(3, page.items().size());
        var user = page.items().get(0);
        assertEquals("user:7", user.externalId());
        assertEquals(NamespaceKind.USER, user.kind());
        assertEquals("seckma95", user.fullPath());
        assertEquals(NamespaceKind.GROUP, page.items().get(1).kind());
        var sub = page.items().get(2);
        assertEquals(NamespaceKind.SUBGROUP, sub.kind());
        assertEquals("10", sub.parentExternalId());
        assertEquals("acme/pay", sub.fullPath());
        assertEquals("2", page.nextCursor());
        assertEquals(Integer.valueOf(3), page.totalCount());
    }

    @Test
    void lastPageHasNoCursorAndNoPersonalNamespace() {
        server.on("/api/v4/groups?min_access_level=10&order_by=path&sort=asc&per_page=2&page=2",
                Reply.json("[{\"id\":12,\"name\":\"Ops\",\"full_path\":\"ops\"}]").withHeader("X-Next-Page", ""));
        var page = provider.listNamespaces(server.spec(GitProviderType.GITLAB, "t"), new PageRequest("2", 2));
        assertEquals(1, page.items().size());
        assertNull(page.nextCursor());
    }

    @Test
    void groupProjectsAreMappedWithCleanCloneUrls() {
        server.on("/api/v4/groups/10/projects?include_subgroups=false&with_shared=false&order_by=path&sort=asc&per_page=50&page=1",
                Reply.json("""
                        [{"id":42,"name":"API","path":"api","path_with_namespace":"acme/api",
                          "http_url_to_repo":"https://gitlab.com/acme/api.git","web_url":"https://gitlab.com/acme/api",
                          "default_branch":"main","visibility":"private","archived":false,"last_activity_at":"2026-11-01T08:30:00.000Z"},
                         {"id":43,"name":"Old","path_with_namespace":"acme/old","http_url_to_repo":"https://gitlab.com/acme/old.git",
                          "default_branch":null,"visibility":"internal","archived":true}]"""));
        var page = provider.listRepositories(server.spec(GitProviderType.GITLAB, "t"), "10", PageRequest.first(50));

        assertEquals(2, page.items().size());
        var api = page.items().getFirst();
        assertEquals("42", api.externalId());
        assertEquals("acme/api", api.fullName());
        assertEquals("https://gitlab.com/acme/api.git", api.cloneUrl().toString());
        assertEquals("main", api.defaultBranch());
        assertEquals(Visibility.PRIVATE, api.visibility());
        assertEquals(Instant.parse("2026-11-01T08:30:00Z"), api.lastActivityAt());
        assertTrue(page.items().get(1).archived());
        assertNull(page.items().get(1).defaultBranch());
        assertNull(page.nextCursor());
    }

    @Test
    void personalProjectsUseTheUsersEndpoint() {
        server.on("/api/v4/users/7/projects?order_by=path&sort=asc&per_page=20&page=1", Reply.json("[]"));
        var page = provider.listRepositories(server.spec(GitProviderType.GITLAB, "t"), "user:7", PageRequest.first(20));
        assertTrue(page.items().isEmpty());
    }

    @Test
    void branchesAndHeadCommit() {
        server.on("/api/v4/projects/42/repository/branches?per_page=100&page=1", Reply.json("""
                [{"name":"main","default":true,"protected":true,"commit":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
                 {"name":"feature/x","default":false,"protected":false,"commit":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]"""));
        var spec = server.spec(GitProviderType.GITLAB, "t");
        var branches = provider.listBranches(spec, "42", PageRequest.first(100));
        assertEquals(2, branches.items().size());
        assertTrue(branches.items().getFirst().isDefault());

        server.on("/api/v4/projects/42/repository/branches/feature%2Fx",
                Reply.json("{\"name\":\"feature/x\",\"commit\":{\"id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}}"));
        assertEquals(Optional.of("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), provider.resolveHeadCommit(spec, "42", "feature/x"));
        assertEquals(Optional.empty(), provider.resolveHeadCommit(spec, "42", "gone"));
    }

    @Test
    void findsGroupByPathThenUserByName() {
        server.on("/api/v4/groups/gitlab-org%2Fsecurity-products?with_projects=false",
                Reply.json("{\"id\":99,\"name\":\"security-products\",\"full_path\":\"gitlab-org/security-products\",\"parent_id\":9970}"));
        var spec = server.spec(GitProviderType.GITLAB, null);
        var group = provider.findNamespace(spec, "/gitlab-org/security-products/").orElseThrow();
        assertEquals("99", group.externalId());
        assertEquals(NamespaceKind.SUBGROUP, group.kind());

        server.on("/api/v4/users?username=awa", Reply.json("[{\"id\":5,\"username\":\"awa\",\"name\":\"Awa\"}]"));
        assertEquals("user:5", provider.findNamespace(spec, "awa").orElseThrow().externalId());
        server.on("/api/v4/users?username=nobody", Reply.json("[]"));
        assertTrue(provider.findNamespace(spec, "nobody").isEmpty());
    }

    @Test
    void anonymousListingIsEmptyAndCursorsAreValidated() {
        var anon = provider.listNamespaces(server.spec(GitProviderType.GITLAB, null), PageRequest.first(10));
        assertTrue(anon.items().isEmpty());
        assertTrue(server.requests.isEmpty(), "no request: would list every public group of the instance");
        assertThrows(IllegalArgumentException.class, () -> provider.listNamespaces(server.spec(GitProviderType.GITLAB, "t"),
                new PageRequest("http://evil/", 10)));
    }

    @Test
    void errorsPropagateAsTypedExceptions() {
        server.on("/api/v4/groups/10/projects", Reply.json(429, "{}").withHeader("Retry-After", "30"));
        var e = assertThrows(GitProviderException.class, () -> provider.listRepositories(
                server.spec(GitProviderType.GITLAB, "t"), "10", PageRequest.first(10)));
        assertEquals(GitProviderException.Kind.RATE_LIMITED, e.kind());
    }
}
