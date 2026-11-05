package com.saytu.scan.git;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Real Git "smart HTTP" server for tests: JDK HttpServer in front of {@code git http-backend} (CGI),
 * protected by HTTP basic authentication. Records the Authorization headers it receives.
 */
final class GitHttpServer implements AutoCloseable {

    private final HttpServer server;
    private final Path projectRoot;
    private final String expectedAuthorization;
    final List<String> receivedAuthorizations = new CopyOnWriteArrayList<>();

    GitHttpServer(Path projectRoot, String expectedAuthorization) throws IOException {
        this.projectRoot = projectRoot;
        this.expectedAuthorization = expectedAuthorization;
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    String url(String repo) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/" + repo;
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth != null) {
                receivedAuthorizations.add(auth);
            }
            if (!expectedAuthorization.equals(auth)) {
                exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"test\"");
                exchange.sendResponseHeaders(401, -1);
                return;
            }
            ProcessBuilder pb = new ProcessBuilder("/usr/bin/git", "http-backend");
            Map<String, String> env = pb.environment();
            env.clear();
            env.put("GIT_PROJECT_ROOT", projectRoot.toString());
            env.put("GIT_HTTP_EXPORT_ALL", "1");
            env.put("PATH_INFO", exchange.getRequestURI().getPath());
            env.put("QUERY_STRING", exchange.getRequestURI().getRawQuery() == null ? "" : exchange.getRequestURI().getRawQuery());
            env.put("REQUEST_METHOD", exchange.getRequestMethod());
            String type = exchange.getRequestHeaders().getFirst("Content-Type");
            env.put("CONTENT_TYPE", type == null ? "" : type);
            String encoding = exchange.getRequestHeaders().getFirst("Content-Encoding");
            if (encoding != null) {
                env.put("HTTP_CONTENT_ENCODING", encoding);
            }
            String protocol = exchange.getRequestHeaders().getFirst("Git-Protocol");
            if (protocol != null) {
                env.put("GIT_PROTOCOL", protocol);
            }
            env.put("REMOTE_USER", "test");
            env.put("REMOTE_ADDR", "127.0.0.1");
            env.put("GIT_CONFIG_NOSYSTEM", "1");
            env.put("GIT_CONFIG_GLOBAL", "/dev/null");
            Process p = pb.start();
            try (OutputStream in = p.getOutputStream(); InputStream body = exchange.getRequestBody()) {
                body.transferTo(in);
            }
            byte[] out = p.getInputStream().readAllBytes();
            int split = indexOf(out, "\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            int sep = 4;
            if (split < 0) {
                split = indexOf(out, "\n\n".getBytes(StandardCharsets.US_ASCII));
                sep = 2;
            }
            String headers = new String(out, 0, Math.max(split, 0), StandardCharsets.ISO_8859_1);
            int status = 200;
            for (String line : headers.split("\r?\n")) {
                int colon = line.indexOf(':');
                if (colon < 0) {
                    continue;
                }
                String name = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                if (name.equalsIgnoreCase("Status")) {
                    status = Integer.parseInt(value.split(" ")[0]);
                } else {
                    exchange.getResponseHeaders().add(name, value);
                }
            }
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(out, split + sep, out.length - split - sep);
            exchange.sendResponseHeaders(status, body.size() == 0 ? -1 : body.size());
            if (body.size() > 0) {
                exchange.getResponseBody().write(body.toByteArray());
            }
        }
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
