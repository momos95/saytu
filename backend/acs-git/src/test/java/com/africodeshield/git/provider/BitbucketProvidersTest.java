package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProviderException.Kind;
import com.africodeshield.git.FakeGitServer;
import com.africodeshield.git.FakeGitServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BitbucketProvidersTest {

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
        // Cloud always targets api.bitbucket.org; tests override the API URL with the fake server.
        return server.spec(GitProviderType.BITBUCKET_CLOUD, token, username, server.url().resolve("/2.0"));
    }

    @Test
    void cloudApiTokenUsesBasicWithEmail() {
        server.on("/2.0/user", Reply.json("{\"username\":\"fatou\",\"display_name\":\"Fatou\"}"));
        var r = new BitbucketCloudProvider(FakeGitServer.client()).testConnection(cloud("ATATT-token", "fatou@corp.sn"));
        assertTrue(r.success(), String.valueOf(r.errorMessage()));
        assertEquals("fatou", r.authenticatedAs());
        String expected = "Basic " + Base64.getEncoder().encodeToString("fatou@corp.sn:ATATT-token".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, server.requests.getFirst().header("Authorization"));
    }

    @Test
    void cloudAccessTokenFallsBackToRepositoriesWhenNotAUser() {
        server.on("/2.0/user", Reply.json(403, "{\"type\":\"error\",\"error\":{\"message\":\"Access token not linked to a user\"}}"));
        server.on("/2.0/repositories?role=member&pagelen=1", Reply.json("{\"values\":[]}"));
        var r = new BitbucketCloudProvider(FakeGitServer.client()).testConnection(cloud("access-token", null));
        assertTrue(r.success(), String.valueOf(r.errorMessage()));
        assertEquals("access token", r.authenticatedAs());
        assertEquals("Bearer access-token", server.requests.getFirst().header("Authorization"));
    }

    @Test
    void cloudBadCredentialsExplainAppPasswordRetirement() {
        server.on("/2.0/user", Reply.json(401, "{}"));
        var r = new BitbucketCloudProvider(FakeGitServer.client()).testConnection(cloud("old-app-password", "fatou"));
        assertEquals(Kind.AUTHENTICATION_FAILED, r.errorKind());
        assertTrue(r.errorMessage().contains("app passwords no longer work"));
    }

    @Test
    void cloudRequiresBitbucketOrgUrl() {
        var spec = new GitConnectionSpec(GitProviderType.BITBUCKET_CLOUD, URI.create("https://bitbucket.corp"), null, null, null, true);
        assertThrows(IllegalArgumentException.class, () -> ProviderEndpoints.apiBase(spec));
        var r = new BitbucketCloudProvider(FakeGitServer.client()).testConnection(spec);
        assertFalse(r.success());
        assertTrue(r.errorMessage().contains("BITBUCKET_DATA_CENTER"));
        var ok = new GitConnectionSpec(GitProviderType.BITBUCKET_CLOUD, URI.create("https://bitbucket.org"), null, null, null, true);
        assertEquals("https://api.bitbucket.org/2.0", ProviderEndpoints.apiBase(ok).toString());
    }

    @Test
    void dataCenterBearerTokenReportsUserAndVersion() {
        server.on("/rest/api/1.0/application-properties",
                Reply.json("{\"version\":\"9.4.3\",\"buildNumber\":\"9004003\",\"displayName\":\"Bitbucket\"}"));
        server.on("/rest/api/1.0/projects?limit=1",
                Reply.json("{\"size\":1,\"limit\":1,\"isLastPage\":false,\"values\":[{\"key\":\"PAY\"}]}")
                        .withHeader("X-AUSERNAME", "ci-audit"));
        var r = new BitbucketDataCenterProvider(FakeGitServer.client())
                .testConnection(server.spec(GitProviderType.BITBUCKET_DATA_CENTER, "BBDC-token"));
        assertTrue(r.success(), String.valueOf(r.errorMessage()));
        assertEquals("ci-audit", r.authenticatedAs());
        assertEquals("Bitbucket 9.4.3", r.serverVersion());
        assertEquals("Bearer BBDC-token", server.requests.get(1).header("Authorization"));
    }

    @Test
    void dataCenterTokenSeeingNoProjectWarns() {
        server.on("/rest/api/1.0/application-properties", Reply.json("{\"version\":\"8.19.0\"}"));
        server.on("/rest/api/1.0/projects?limit=1", Reply.json("{\"size\":0,\"isLastPage\":true,\"values\":[]}"));
        var r = new BitbucketDataCenterProvider(FakeGitServer.client())
                .testConnection(server.spec(GitProviderType.BITBUCKET_DATA_CENTER, "t"));
        assertTrue(r.success());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("sees no project")));
    }

    @Test
    void dataCenterInvalidTokenFails() {
        server.on("/rest/api/1.0/application-properties", Reply.json("{\"version\":\"9.0.0\"}"));
        server.on("/rest/api/1.0/projects?limit=1", Reply.json(401,
                "{\"errors\":[{\"message\":\"Authentication failed. Please check your credentials and try again.\"}]}"));
        var r = new BitbucketDataCenterProvider(FakeGitServer.client())
                .testConnection(server.spec(GitProviderType.BITBUCKET_DATA_CENTER, "bad"));
        assertEquals(Kind.AUTHENTICATION_FAILED, r.errorKind());
        assertTrue(r.errorMessage().contains("check your credentials"));
    }

    @Test
    void dataCenterWrongProductIsDetected() {
        server.on("/rest/api/1.0/application-properties", Reply.json("{\"name\":\"something else\"}"));
        var r = new BitbucketDataCenterProvider(FakeGitServer.client())
                .testConnection(server.spec(GitProviderType.BITBUCKET_DATA_CENTER, "t"));
        assertEquals(Kind.UNEXPECTED_RESPONSE, r.errorKind());
    }
}
