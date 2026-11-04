package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.domain.NamespaceKind;
import com.africodeshield.core.git.GitProvider.PageRequest;
import com.africodeshield.core.git.GitProvider.Visibility;
import com.africodeshield.git.FakeGitServer;
import com.africodeshield.git.FakeGitServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitHubDiscoveryTest {

    private FakeGitServer server;
    private GitHubProvider provider;

    @BeforeEach
    void start() throws Exception {
        server = new FakeGitServer();
        provider = new GitHubProvider(FakeGitServer.client());
        server.on("/api/v3/user", Reply.json("{\"login\":\"moussa\"}"));
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void userThenOrganisationsWithLinkHeaderPagination() {
        server.on("/api/v3/user/orgs?per_page=30&page=1", Reply.json("[{\"login\":\"acme\",\"id\":1},{\"login\":\"sonatel-oss\",\"id\":2}]")
                .withHeader("Link", "<https://api.github.com/user/orgs?per_page=30&page=2>; rel=\"next\", "
                        + "<https://api.github.com/user/orgs?per_page=30&page=3>; rel=\"last\""));
        var page = provider.listNamespaces(server.spec(GitProviderType.GITHUB, "t"), PageRequest.first(30));
        assertEquals(3, page.items().size());
        assertEquals("user:moussa", page.items().getFirst().externalId());
        assertEquals(NamespaceKind.ORGANIZATION, page.items().get(1).kind());
        assertEquals(server.url() + "/acme", page.items().get(1).webUrl().toString());
        assertEquals("2", page.nextCursor(), "cursor is a page number, never the Link URL");

        server.on("/api/v3/user/orgs?per_page=30&page=2", Reply.json("[]")
                .withHeader("Link", "<https://api.github.com/user/orgs?page=1>; rel=\"prev\""));
        var last = provider.listNamespaces(server.spec(GitProviderType.GITHUB, "t"), new PageRequest("2", 30));
        assertNull(last.nextCursor());
        assertTrue(last.items().isEmpty());
    }

    @Test
    void orgRepositories() {
        server.on("/api/v3/orgs/acme/repos?type=all&per_page=100&page=1&sort=full_name", Reply.json("""
                [{"id":1,"name":"api","full_name":"acme/api","clone_url":"https://github.com/acme/api.git",
                  "html_url":"https://github.com/acme/api","default_branch":"main","private":true,"visibility":"private",
                  "archived":false,"pushed_at":"2026-10-30T12:00:00Z"},
                 {"id":2,"name":"site","full_name":"acme/site","clone_url":"https://github.com/acme/site.git",
                  "default_branch":"master","private":false,"archived":true}]"""));
        var page = provider.listRepositories(server.spec(GitProviderType.GITHUB, "t"), "acme", PageRequest.first(100));
        assertEquals(2, page.items().size());
        assertEquals("acme/api", page.items().getFirst().externalId());
        assertEquals(Visibility.PRIVATE, page.items().getFirst().visibility());
        assertEquals(Visibility.PUBLIC, page.items().get(1).visibility());
        assertTrue(page.items().get(1).archived());
    }

    @Test
    void ownUserReposIncludePrivateOnesOtherUsersUsePublicEndpoint() {
        server.on("/api/v3/user/repos?affiliation=owner&per_page=10&page=1&sort=full_name", Reply.json("[]"));
        provider.listRepositories(server.spec(GitProviderType.GITHUB, "t"), "user:moussa", PageRequest.first(10));
        assertTrue(server.requests.stream().anyMatch(r -> r.pathAndQuery().startsWith("/api/v3/user/repos?affiliation=owner")));

        server.on("/api/v3/users/octocat/repos?type=owner&per_page=10&page=1&sort=full_name", Reply.json("[]"));
        provider.listRepositories(server.spec(GitProviderType.GITHUB, "t"), "user:octocat", PageRequest.first(10));
        assertTrue(server.requests.stream().anyMatch(r -> r.pathAndQuery().startsWith("/api/v3/users/octocat/repos")));
    }

    @Test
    void findsPublicOrganisationOrUserByName() {
        server.on("/api/v3/users/kubernetes", Reply.json("{\"login\":\"kubernetes\",\"type\":\"Organization\",\"html_url\":\"https://github.com/kubernetes\"}"));
        var org = provider.findNamespace(server.spec(GitProviderType.GITHUB, null), "kubernetes").orElseThrow();
        assertEquals("kubernetes", org.externalId());
        assertEquals(NamespaceKind.ORGANIZATION, org.kind());

        server.on("/api/v3/users/torvalds", Reply.json("{\"login\":\"torvalds\",\"type\":\"User\"}"));
        assertEquals("user:torvalds", provider.findNamespace(server.spec(GitProviderType.GITHUB, null), "torvalds").orElseThrow().externalId());
        assertTrue(provider.findNamespace(server.spec(GitProviderType.GITHUB, null), "does-not-exist").isEmpty());
        assertTrue(provider.findNamespace(server.spec(GitProviderType.GITHUB, null), "a/b").isEmpty());
    }

    @Test
    void branchesAndHead() {
        server.on("/api/v3/repos/acme/api/branches?per_page=100&page=1",
                Reply.json("[{\"name\":\"main\",\"commit\":{\"sha\":\"cccccccccccccccccccccccccccccccccccccccc\"},\"protected\":true}]"));
        var spec = server.spec(GitProviderType.GITHUB, "t");
        var b = provider.listBranches(spec, "acme/api", PageRequest.first(100));
        assertEquals("main", b.items().getFirst().name());
        assertTrue(b.items().getFirst().isProtected());

        server.on("/api/v3/repos/acme/api/branches/release%2F1.0",
                Reply.json("{\"name\":\"release/1.0\",\"commit\":{\"sha\":\"dddddddddddddddddddddddddddddddddddddddd\"}}"));
        assertEquals(Optional.of("dddddddddddddddddddddddddddddddddddddddd"), provider.resolveHeadCommit(spec, "acme/api", "release/1.0"));
    }
}
