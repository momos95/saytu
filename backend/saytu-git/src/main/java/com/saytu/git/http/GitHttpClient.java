package com.saytu.git.http;

import com.saytu.core.git.GitProviderException;
import com.saytu.core.git.GitProviderException.Kind;
import com.saytu.git.json.JsonNode;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The only component that sends requests to Git platforms.
 * <ul>
 *   <li>every destination goes through {@link EndpointPolicy} first;</li>
 *   <li>redirects are never followed (a token must not be replayed to another host);</li>
 *   <li>response bodies are capped ({@link Settings#maxBodyBytes()});</li>
 *   <li>nothing is logged: callers receive typed exceptions whose messages never include headers.</li>
 * </ul>
 * Thread-safe; one instance is shared by all providers.
 */
public final class GitHttpClient {

    /**
     * @param proxy {@code null} for direct connections; {@link ProxySelector#getDefault()} honours the
     *              standard {@code https.proxyHost} / {@code http.nonProxyHosts} JVM properties
     */
    public record Settings(Duration connectTimeout, Duration requestTimeout, int maxBodyBytes, String userAgent,
                           SSLContext sslContext, ProxySelector proxy) {
        public Settings {
            Objects.requireNonNull(connectTimeout, "connectTimeout");
            Objects.requireNonNull(requestTimeout, "requestTimeout");
            if (maxBodyBytes < 1024) {
                throw new IllegalArgumentException("maxBodyBytes too small");
            }
            userAgent = userAgent == null || userAgent.isBlank() ? "SAYTU" : userAgent;
        }

        public static Settings defaults() {
            return new Settings(Duration.ofSeconds(10), Duration.ofSeconds(30), 8 * 1024 * 1024,
                    "SAYTU", null, ProxySelector.getDefault());
        }
    }

    /** Raw outcome of a request: any status, parsed JSON body when the response is JSON. */
    public record Response(int status, Map<String, List<String>> headers, JsonNode body) {
        public Response {
            headers = headers == null ? Map.of() : headers;
            body = body == null ? JsonNode.MISSING : body;
        }

        public boolean isSuccess() {
            return status >= 200 && status < 300;
        }

        public Optional<String> header(String name) {
            return HttpErrorClassifier.header(headers, name.toLowerCase(Locale.ROOT));
        }
    }

    private final HttpClient http;
    private final Settings settings;
    private final EndpointPolicy policy;
    private final Clock clock;

    public GitHttpClient(Settings settings, EndpointPolicy policy, Clock clock) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.clock = clock == null ? Clock.systemUTC() : clock;
        HttpClient.Builder builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(settings.connectTimeout())
                .version(HttpClient.Version.HTTP_1_1);
        if (settings.sslContext() != null) {
            builder.sslContext(settings.sslContext());
        }
        if (settings.proxy() != null) {
            builder.proxy(settings.proxy());
        }
        this.http = builder.build();
    }

    public EndpointPolicy policy() {
        return policy;
    }

    public Clock clock() {
        return clock;
    }

    /** GET returning the response whatever its status (network and policy errors still throw). */
    public Response get(URI uri, Auth auth) {
        policy.check(uri);
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(settings.requestTimeout())
                .header("Accept", "application/json")
                .header("User-Agent", settings.userAgent());
        auth.header().ifPresent(h -> request.header(h[0], h[1]));
        HttpResponse<InputStream> response;
        try {
            response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw HttpErrorClassifier.fromIOException(e, uri);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GitProviderException(Kind.UNREACHABLE, "Interrupted while contacting " + uri.getHost());
        }
        Map<String, List<String>> headers = response.headers().map();
        String body = readCapped(response, uri);
        return new Response(response.statusCode(), headers, parseIfJson(body, headers, response.statusCode(), uri));
    }

    /** GET that throws a classified {@link GitProviderException} for any non-2xx status. */
    public Response getOk(URI uri, Auth auth) {
        Response r = get(uri, auth);
        if (!r.isSuccess()) {
            throw HttpErrorClassifier.fromResponse(r.status(), r.headers(), r.body(), uri, clock);
        }
        return r;
    }

    private String readCapped(HttpResponse<InputStream> response, URI uri) {
        try (InputStream in = response.body()) {
            byte[] data = in.readNBytes(settings.maxBodyBytes() + 1);
            if (data.length > settings.maxBodyBytes()) {
                throw new GitProviderException(Kind.UNEXPECTED_RESPONSE, "Response from " + uri.getHost()
                        + " exceeds " + settings.maxBodyBytes() + " bytes");
            }
            return new String(data, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw HttpErrorClassifier.fromIOException(e, uri);
        }
    }

    private static JsonNode parseIfJson(String body, Map<String, List<String>> headers, int status, URI uri) {
        String type = HttpErrorClassifier.header(headers, "content-type").orElse("").toLowerCase(Locale.ROOT);
        boolean looksJson = type.contains("json") || (type.isEmpty() && body.stripLeading().startsWith("{"));
        if (body.isBlank() || !looksJson) {
            if (status >= 200 && status < 300 && !body.isBlank()) {
                throw new GitProviderException(Kind.UNEXPECTED_RESPONSE, uri.getHost() + " did not answer with JSON ("
                        + (type.isEmpty() ? "no content type" : type) + "): is this the right platform and URL?");
            }
            return JsonNode.MISSING;
        }
        try {
            return JsonNode.parse(body);
        } catch (JsonNode.JsonParseException e) {
            if (status >= 200 && status < 300) {
                throw new GitProviderException(Kind.UNEXPECTED_RESPONSE, uri.getHost() + " returned malformed JSON");
            }
            return JsonNode.MISSING;
        }
    }
}
