package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.domain.NamespaceKind;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProvider.PageRequest;
import com.saytu.core.git.GitProvider.Visibility;
import com.saytu.git.FakeGitServer;
import com.saytu.git.FakeGitServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BitbucketDiscoveryTest {

    private FakeGitServer server;

    @BeforeEach
    void start() throws Exception {
        server = new FakeGitServer();
    }

    @AfterEach
    void stop() {
        server.close();
    }

    private GitConnectionSpec cloud(String token, String username) {
        return server.spec(GitProviderType.BITBUCKET_CLOUD, token, username, server.url().resolve("/2.0"));
    }

    @Test
    void cloudWorkspacesComeFromUserWorkspaces() {
        server.on("/2.0/user/workspaces?pagelen=50&page=1", Reply.json("""
                {"pagelen":50,"size":2,"page":1,"next":"https://api.bitbucket.org/2.0/user/workspaces?page=2",
                 "values":[{"workspace":{"slug":"acme","name":"Acme","links":{"html":{"href":"https://bitbucket.org/acme/"}}}},
                           {"slug":"bare-shape","name":"Bare"}]}"""));
        var page = new BitbucketCloudProvider(FakeGitServer.client())
                .listNamespaces(cloud("t", "me@corp.sn"), PageRequest.first(50));
        assertEquals(2, page.items().size());
        assertEquals("acme", page.items().getFirst().externalId());
        assertEquals(NamespaceKind.WORKSPACE, page.items().getFirst().kind());
        assertEquals("bare-shape", page.items().get(1).externalId());
        assertEquals("2", page.nextCursor());
        assertEquals(Integer.valueOf(2), page.totalCount());
    }

    @Test
    void cloudAccessTokenListsNothingAndAddsWorkspaceByName() {
        server.on("/2.0/user/workspaces?pagelen=50&page=1", Reply.json(403, "{\"type\":\"error\"}"));
        var provider = new BitbucketCloudProvider(FakeGitServer.client());
        assertTrue(provider.listNamespaces(cloud("access", null), PageRequest.first(50)).items().isEmpty());

        server.on("/2.0/repositories/acme?pagelen=1", Reply.json("{\"values\":[]}"));
        var ws = provider.findNamespace(cloud("access", null), "acme").orElseThrow();
        assertEquals("acme", ws.externalId());
        assertEquals("https://bitbucket.org/acme", ws.webUrl().toString());
        assertTrue(provider.findNamespace(cloud("access", null), "missing").isEmpty());
    }

    @Test
    void cloudRepositoriesStripUserInfoFromCloneLinks() {
        server.on("/2.0/repositories/acme?pagelen=100&page=1&sort=full_name", Reply.json("""
                {"values":[{"slug":"api","name":"API","full_name":"acme/api","is_private":true,
                  "mainbranch":{"name":"develop"},"updated_on":"2026-10-01T10:00:00.000000+00:00",
                  "links":{"html":{"href":"https://bitbucket.org/acme/api"},
                           "clone":[{"name":"https","href":"https://fatou@bitbucket.org/acme/api.git"},
                                    {"name":"ssh","href":"git@bitbucket.org:acme/api.git"}]}}]}"""));
        var page = new BitbucketCloudProvider(FakeGitServer.client())
                .listRepositories(cloud("t", "me@corp.sn"), "acme", PageRequest.first(100));
        var repo = page.items().getFirst();
        assertEquals("acme/api", repo.externalId());
        assertEquals("https://bitbucket.org/acme/api.git", repo.cloneUrl().toString());
        assertEquals("develop", repo.defaultBranch());
        assertEquals(Visibility.PRIVATE, repo.visibility());
        assertNull(page.nextCursor());
    }

    @Test
    void cloudBranchesAndHead() {
        server.on("/2.0/repositories/acme/api/refs/branches?pagelen=100&page=1", Reply.json(
                "{\"values\":[{\"name\":\"main\",\"target\":{\"hash\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"}}]}"));
        var provider = new BitbucketCloudProvider(FakeGitServer.client());
        assertEquals("main", provider.listBranches(cloud("t", "me@corp.sn"), "acme/api", PageRequest.first(100))
                .items().getFirst().name());
        server.on("/2.0/repositories/acme/api/refs/branches/main", Reply.json(
                "{\"name\":\"main\",\"target\":{\"hash\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"}}"));
        assertEquals(Optional.of("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
                provider.resolveHeadCommit(cloud("t", "me@corp.sn"), "acme/api", "main"));
        assertThrows(IllegalArgumentException.class,
                () -> provider.resolveHeadCommit(cloud("t", "me@corp.sn"), "acme/../x", "main"));
    }

    @Test
    void dataCenterProjectsReposAndBranchesWithOffsetPagination() {
        var provider = new BitbucketDataCenterProvider(FakeGitServer.client());
        var spec = server.spec(GitProviderType.BITBUCKET_DATA_CENTER, "t");
        server.on("/rest/api/1.0/projects?limit=25&start=0", Reply.json("""
                {"size":1,"limit":25,"isLastPage":false,"nextPageStart":25,"start":0,
                 "values":[{"key":"PAY","id":1,"name":"Payments","links":{"self":[{"href":"https://bb.corp/projects/PAY"}]}}]}"""));
        var projects = provider.listNamespaces(spec, PageRequest.first(25));
        assertEquals("PAY", projects.items().getFirst().externalId());
        assertEquals(NamespaceKind.PROJECT, projects.items().getFirst().kind());
        assertEquals("25", projects.nextCursor());

        server.on("/rest/api/1.0/projects/PAY/repos?limit=25&start=0", Reply.json("""
                {"isLastPage":true,"values":[{"slug":"core","name":"Core","project":{"key":"PAY"},"public":false,"archived":false,
                  "links":{"clone":[{"name":"http","href":"https://admin@bb.corp/scm/pay/core.git"},
                                    {"name":"ssh","href":"ssh://git@bb.corp:7999/pay/core.git"}],
                           "self":[{"href":"https://bb.corp/projects/PAY/repos/core/browse"}]}}]}"""));
        var repos = provider.listRepositories(spec, "PAY", PageRequest.first(25));
        var core = repos.items().getFirst();
        assertEquals("PAY/core", core.externalId());
        assertEquals("https://bb.corp/scm/pay/core.git", core.cloneUrl().toString());
        assertNull(repos.nextCursor());

        server.on("/rest/api/1.0/projects/PAY/repos/core/branches?limit=100&start=0", Reply.json("""
                {"isLastPage":true,"values":[{"displayId":"master","latestCommit":"ffffffffffffffffffffffffffffffffffffffff","isDefault":true},
                                            {"displayId":"develop","latestCommit":"1111111111111111111111111111111111111111","isDefault":false}]}"""));
        var branches = provider.listBranches(spec, "PAY/core", PageRequest.first(100));
        assertTrue(branches.items().getFirst().isDefault());

        server.on("/rest/api/1.0/projects/PAY/repos/core/branches?limit=100&filterText=develop", Reply.json("""
                {"values":[{"displayId":"develop-old","latestCommit":"2222222222222222222222222222222222222222"},
                           {"displayId":"develop","latestCommit":"1111111111111111111111111111111111111111"}]}"""));
        assertEquals(Optional.of("1111111111111111111111111111111111111111"), provider.resolveHeadCommit(spec, "PAY/core", "develop"));
        assertThrows(IllegalArgumentException.class, () -> provider.listBranches(spec, "PAY/core/x", PageRequest.first(10)));
    }
}
