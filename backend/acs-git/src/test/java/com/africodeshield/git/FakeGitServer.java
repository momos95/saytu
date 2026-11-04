package com.africodeshield.git;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.security.SensitiveValue;
import com.africodeshield.git.http.EndpointPolicy;
import com.africodeshield.git.http.GitHttpClient;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Local HTTP server (JDK built-in) replaying canned platform responses, and recording requests so
 * tests can assert which headers were sent. Real HTTP over loopback: the client code under test is
 * exactly the production code.
 */
public final class FakeGitServer implements AutoCloseable {

    public record Reply(int status, Map<String, String> headers, String body) {
        public static Reply json(String body) {
            return new Reply(200, Map.of("Content-Type", "application/json"), body);
        }

        public static Reply json(int status, String body) {
            return new Reply(status, Map.of("Content-Type", "application/json"), body);
        }

        public Reply withHeader(String name, String value) {
            var h = new java.util.HashMap<>(headers);
            h.put(name, value);
            return new Reply(status, h, body);
        }
    }

    public record Recorded(String pathAndQuery, Map<String, List<String>> headers) {
        public String header(String name) {
            return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                    .findFirst().map(e -> e.getValue().getFirst()).orElse(null);
        }
    }

    public static final Instant NOW = Instant.parse("2026-11-04T10:00:00Z");

    private final HttpServer server;
    private final Map<String, Reply> routes = new ConcurrentHashMap<>();
    public final List<Recorded> requests = new CopyOnWriteArrayList<>();

    public FakeGitServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String pq = exchange.getRequestURI().getRawPath()
                    + (exchange.getRequestURI().getRawQuery() == null ? "" : "?" + exchange.getRequestURI().getRawQuery());
            requests.add(new Recorded(pq, Map.copyOf(exchange.getRequestHeaders())));
            Reply reply = routes.getOrDefault(pq, routes.getOrDefault(exchange.getRequestURI().getRawPath(),
                    Reply.json(404, "{\"message\":\"404 Not Found\"}")));
            byte[] body = reply.body().getBytes(StandardCharsets.UTF_8);
            reply.headers().forEach((k, v) -> exchange.getResponseHeaders().add(k, v));
            exchange.sendResponseHeaders(reply.status(), body.length == 0 ? -1 : body.length);
            if (body.length > 0) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            exchange.close();
        });
        server.start();
    }

    /** Route by exact path+query, or by path alone. */
    public FakeGitServer on(String pathAndQuery, Reply reply) {
        routes.put(pathAndQuery, reply);
        return this;
    }

    public URI url() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    public static GitHttpClient client() {
        return client(1024 * 1024);
    }

    public static GitHttpClient client(int maxBody) {
        return new GitHttpClient(new GitHttpClient.Settings(Duration.ofSeconds(2), Duration.ofSeconds(5), maxBody,
                "AfriCodeShield-test", null, null),
                new EndpointPolicy(true, true, null), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    public GitConnectionSpec spec(GitProviderType type, String token) {
        return spec(type, token, null, null);
    }

    public GitConnectionSpec spec(GitProviderType type, String token, String username, URI apiUrl) {
        return new GitConnectionSpec(type, url(), apiUrl, username, token == null ? null : SensitiveValue.of(token), true);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
