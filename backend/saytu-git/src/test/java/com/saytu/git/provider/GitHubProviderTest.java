package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProviderException.Kind;
import com.saytu.git.FakeGitServer;
import com.saytu.git.FakeGitServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitHubProviderTest {

    private FakeGitServer server;
    private GitHubProvider provider;

    @BeforeEach
    void start() throws Exception {
        server = new FakeGitServer();
        provider = new GitHubProvider(FakeGitServer.client());
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void enterpriseServerClassicTokenWithScopesAndExpiry() {
        server.on("/api/v3/user", Reply.json("{\"login\":\"moussa\",\"id\":1}")
                .withHeader("X-OAuth-Scopes", "repo, read:org")
                .withHeader("X-GitHub-Enterprise-Version", "3.17.2")
                .withHeader("github-authentication-token-expiration", "2026-11-12 09:00:00 UTC"));
        var r = provider.testConnection(server.spec(GitProviderType.GITHUB, "ghp_x"));
        assertTrue(r.success(), String.valueOf(r.errorMessage()));
        assertEquals("moussa", r.authenticatedAs());
        assertEquals("GitHub Enterprise Server 3.17.2", r.serverVersion());
        assertEquals(List.of("repo", "read:org"), r.grantedScopes());
        assertEquals(Instant.parse("2026-11-12T09:00:00Z"), r.tokenExpiresAt());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("expires in 7 days")), r.warnings().toString());
        assertEquals("Bearer ghp_x", server.requests.getFirst().header("Authorization"));
    }

    @Test
    void classicTokenWithoutRepoOrOrgScopesWarns() {
        server.on("/api/v3/user", Reply.json("{\"login\":\"m\"}").withHeader("X-OAuth-Scopes", "public_repo"));
        var r = provider.testConnection(server.spec(GitProviderType.GITHUB, "t"));
        assertTrue(r.success());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("only public repositories")));
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("read:org")));
    }

    @Test
    void fineGrainedTokenIsDescribedNotVerified() {
        server.on("/api/v3/user", Reply.json("{\"login\":\"m\"}"));
        var r = provider.testConnection(server.spec(GitProviderType.GITHUB, "github_pat_x"));
        assertTrue(r.success());
        assertTrue(r.grantedScopes().isEmpty());
        assertTrue(r.warnings().stream().anyMatch(w -> w.startsWith("Fine-grained")));
        assertEquals("github.com", r.serverVersion());
    }

    @Test
    void rateLimitIsReported() {
        server.on("/api/v3/user", Reply.json(403, "{\"message\":\"API rate limit exceeded\"}")
                .withHeader("x-ratelimit-remaining", "0")
                .withHeader("x-ratelimit-reset", String.valueOf(FakeGitServer.NOW.getEpochSecond() + 600)));
        var r = provider.testConnection(server.spec(GitProviderType.GITHUB, "t"));
        assertEquals(Kind.RATE_LIMITED, r.errorKind());
        assertTrue(r.errorMessage().contains("Retry in 600 s"), r.errorMessage());
    }

    @Test
    void anonymousUsesRateLimitEndpoint() {
        server.on("/api/v3/rate_limit", Reply.json("{\"rate\":{\"limit\":60}}"));
        var r = provider.testConnection(server.spec(GitProviderType.GITHUB, null));
        assertTrue(r.success());
        assertTrue(r.warnings().stream().anyMatch(w -> w.startsWith("Anonymous")));
    }

    @Test
    void githubComUsesApiHost() {
        var spec = new GitConnectionSpec(GitProviderType.GITHUB, URI.create("https://github.com/"), null, null, null, true);
        assertEquals("https://api.github.com", ProviderEndpoints.apiBase(spec).toString());
        var ghes = new GitConnectionSpec(GitProviderType.GITHUB, URI.create("https://git.corp.example"), null, null, null, true);
        assertEquals("https://git.corp.example/api/v3", ProviderEndpoints.apiBase(ghes).toString());
    }

    @Test
    void wrongProviderTypeIsAProgrammingError() {
        var spec = server.spec(GitProviderType.GITLAB, "t");
        try {
            provider.testConnection(spec);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("expected IllegalArgumentException");
    }

    @Test
    void expirationParsing() {
        assertEquals(Instant.parse("2026-12-01T11:00:00Z"), GitHubProvider.parseExpiration("2026-12-01 12:00:00 +0100"));
        assertEquals(null, GitHubProvider.parseExpiration("garbage"));
        assertFalse(GitHubProvider.splitScopes(" ").iterator().hasNext());
    }
}
