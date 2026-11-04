package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitProviderException.Kind;
import com.africodeshield.git.FakeGitServer;
import com.africodeshield.git.FakeGitServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitLabProviderTest {

    private FakeGitServer server;
    private GitLabProvider provider;

    @BeforeEach
    void start() throws Exception {
        server = new FakeGitServer();
        provider = new GitLabProvider(FakeGitServer.client());
        server.on("/api/v4/user", Reply.json("{\"id\":7,\"username\":\"awa.diop\",\"state\":\"active\",\"bot\":false}"));
        server.on("/api/v4/version", Reply.json("{\"version\":\"17.11.2-ee\",\"revision\":\"abc\"}"));
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void validReadOnlyTokenSucceedsWithScopesExpiryAndVersion() {
        server.on("/api/v4/personal_access_tokens/self", Reply.json("""
                {"id":4,"name":"acs","revoked":false,"active":true,"scopes":["read_api","read_repository"],
                 "expires_at":"2027-03-01"}"""));
        var r = provider.testConnection(server.spec(GitProviderType.GITLAB, "glpat-validtoken"));
        assertTrue(r.success(), String.valueOf(r.errorMessage()));
        assertEquals("awa.diop", r.authenticatedAs());
        assertEquals("17.11.2-ee", r.serverVersion());
        assertEquals(List.of("read_api", "read_repository"), r.grantedScopes());
        assertEquals(Instant.parse("2027-03-02T00:00:00Z"), r.tokenExpiresAt());
        assertTrue(securityWarnings(r).isEmpty(), r.warnings().toString());
        assertEquals("glpat-validtoken", server.requests.getFirst().header("PRIVATE-TOKEN"));
    }

    @Test
    void missingScopesFailWithInsufficientPermissions() {
        server.on("/api/v4/personal_access_tokens/self", Reply.json(
                "{\"active\":true,\"revoked\":false,\"scopes\":[\"read_user\"],\"expires_at\":null}"));
        var r = provider.testConnection(server.spec(GitProviderType.GITLAB, "t"));
        assertFalse(r.success());
        assertEquals(Kind.INSUFFICIENT_PERMISSIONS, r.errorKind());
        assertTrue(r.errorMessage().contains("read_api, read_repository"), r.errorMessage());
    }

    @Test
    void writeScopesProduceLeastPrivilegeWarningAndExpirySoonWarning() {
        server.on("/api/v4/personal_access_tokens/self", Reply.json(
                "{\"active\":true,\"revoked\":false,\"scopes\":[\"api\"],\"expires_at\":\"2026-11-10\"}"));
        var r = provider.testConnection(server.spec(GitProviderType.GITLAB, "t"));
        assertTrue(r.success());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("write access")), r.warnings().toString());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("expires in 6 days")), r.warnings().toString());
    }

    @Test
    void olderGitLabWithoutSelfEndpointWarns() {
        var r = provider.testConnection(server.spec(GitProviderType.GITLAB, "t"));
        assertTrue(r.success());
        assertTrue(securityWarnings(r).getFirst().contains("could not be verified"));
    }

    @Test
    void revokedTokenFails() {
        server.on("/api/v4/personal_access_tokens/self", Reply.json(
                "{\"active\":false,\"revoked\":true,\"scopes\":[\"api\"]}"));
        var r = provider.testConnection(server.spec(GitProviderType.GITLAB, "t"));
        assertEquals(Kind.AUTHENTICATION_FAILED, r.errorKind());
    }

    @Test
    void invalidTokenFailsWithAuthenticationError() {
        server.on("/api/v4/user", Reply.json(401, "{\"message\":\"401 Unauthorized\"}"));
        var r = provider.testConnection(server.spec(GitProviderType.GITLAB, "bad"));
        assertFalse(r.success());
        assertEquals(Kind.AUTHENTICATION_FAILED, r.errorKind());
        assertFalse(r.errorMessage().contains("bad"));
    }

    @Test
    void anonymousAccessListsPublicProjectsOnly() {
        server.on("/api/v4/projects?per_page=1&simple=true&visibility=public", Reply.json("[]"));
        var r = provider.testConnection(server.spec(GitProviderType.GITLAB, null));
        assertTrue(r.success());
        assertNull(r.authenticatedAs());
        assertTrue(r.warnings().stream().anyMatch(w -> w.startsWith("Anonymous")));
        assertTrue(r.warnings().stream().anyMatch(w -> w.startsWith("Plain HTTP")));
        assertNull(server.requests.getFirst().header("PRIVATE-TOKEN"));
    }

    @Test
    void gitlabUnderSubPathKeepsThePath() {
        var spec = new com.africodeshield.core.git.GitConnectionSpec(GitProviderType.GITLAB,
                server.url().resolve("/gitlab/"), null, null, null, true);
        assertEquals(server.url() + "/gitlab/api/v4", ProviderEndpoints.apiBase(spec).toString());
    }

    /** Warnings other than the plain-HTTP one caused by the local test server. */
    private static List<String> securityWarnings(com.africodeshield.core.git.GitProvider.ConnectionTestResult r) {
        return r.warnings().stream().filter(w -> !w.startsWith("Plain HTTP")).toList();
    }

    @Test
    void scopeRules() {
        assertEquals(List.of(), GitLabProvider.missingScopes(List.of("api")));
        assertEquals(List.of("read_repository"), GitLabProvider.missingScopes(List.of("read_api")));
        assertEquals(List.of(), GitLabProvider.missingScopes(List.of("read_api", "write_repository")));
        assertNull(GitLabProvider.parseDate("not a date"));
    }
}
