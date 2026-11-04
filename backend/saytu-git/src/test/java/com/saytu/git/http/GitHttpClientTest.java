package com.saytu.git.http;

import com.saytu.core.git.GitProviderException;
import com.saytu.core.git.GitProviderException.Kind;
import com.saytu.core.security.SensitiveValue;
import com.saytu.git.FakeGitServer;
import com.saytu.git.FakeGitServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitHttpClientTest {

    private FakeGitServer server;

    @BeforeEach
    void start() throws Exception {
        server = new FakeGitServer();
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void sendsAuthHeaderAndParsesJson() {
        server.on("/ping", Reply.json("{\"ok\":true}"));
        var r = FakeGitServer.client().getOk(server.url().resolve("/ping"), Auth.bearer(SensitiveValue.of("s3cret")));
        assertTrue(r.body().get("ok").asBoolean(false));
        assertEquals("Bearer s3cret", server.requests.getFirst().header("Authorization"));
        assertEquals("SAYTU-test", server.requests.getFirst().header("User-Agent"));
    }

    @Test
    void anonymousRequestsCarryNoAuthorization() {
        server.on("/ping", Reply.json("{}"));
        FakeGitServer.client().getOk(server.url().resolve("/ping"), Auth.none());
        assertNull(server.requests.getFirst().header("Authorization"));
    }

    @Test
    void redirectsAreNeverFollowed() {
        server.on("/moved", new Reply(302, Map.of("Location", server.url() + "/target"), ""));
        server.on("/target", Reply.json("{}"));
        var e = assertThrows(GitProviderException.class,
                () -> FakeGitServer.client().getOk(server.url().resolve("/moved"), Auth.bearer(SensitiveValue.of("t"))));
        assertEquals(Kind.UNEXPECTED_RESPONSE, e.kind());
        assertEquals(1, server.requests.size(), "the token must not be replayed to the redirect target");
    }

    @Test
    void errorMessagesNeverContainTheToken() {
        server.on("/x", Reply.json(401, "{\"message\":\"401 Unauthorized\"}"));
        var e = assertThrows(GitProviderException.class,
                () -> FakeGitServer.client().getOk(server.url().resolve("/x"), Auth.header("PRIVATE-TOKEN", SensitiveValue.of("glpat-TOPSECRET123"))));
        assertEquals(Kind.AUTHENTICATION_FAILED, e.kind());
        assertFalse(e.getMessage().contains("TOPSECRET"));
        assertTrue(e.getMessage().contains("401 Unauthorized"));
    }

    @Test
    void oversizedBodiesAreRejected() {
        server.on("/big", Reply.json("{\"a\":\"" + "x".repeat(5000) + "\"}"));
        var e = assertThrows(GitProviderException.class,
                () -> FakeGitServer.client(2048).getOk(server.url().resolve("/big"), Auth.none()));
        assertTrue(e.getMessage().contains("exceeds"));
    }

    @Test
    void htmlInsteadOfJsonIsReported() {
        server.on("/login", new Reply(200, Map.of("Content-Type", "text/html"), "<html>login</html>"));
        var e = assertThrows(GitProviderException.class,
                () -> FakeGitServer.client().getOk(server.url().resolve("/login"), Auth.none()));
        assertEquals(Kind.UNEXPECTED_RESPONSE, e.kind());
        assertTrue(e.getMessage().contains("right platform"));
    }

    @Test
    void policyIsAppliedBeforeAnyRequest() {
        var strictClient = new GitHttpClient(GitHttpClient.Settings.defaults(), EndpointPolicy.strict(), Clock.systemUTC());
        var e = assertThrows(GitProviderException.class,
                () -> strictClient.get(server.url().resolve("/ping"), Auth.none()));
        assertEquals(Kind.BLOCKED_BY_POLICY, e.kind());
        assertTrue(server.requests.isEmpty());
    }

    @Test
    void connectionRefusedIsUnreachable() {
        var url = server.url().resolve("/x");
        server.close();
        var e = assertThrows(GitProviderException.class, () -> FakeGitServer.client().get(url, Auth.none()));
        assertEquals(Kind.UNREACHABLE, e.kind());
    }

    @Test
    void authToStringIsMasked() {
        assertFalse(Auth.bearer(SensitiveValue.of("abc123")).toString().contains("abc123"));
        assertFalse(Auth.basic("me@x.org", SensitiveValue.of("abc123")).toString().contains("abc123"));
        assertThrows(IllegalArgumentException.class, () -> Auth.basic("a:b", SensitiveValue.of("x")));
    }
}
