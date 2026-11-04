package com.saytu.app.git;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.time.Duration;

/**
 * Outgoing calls to Git platforms (prefix {@code saytu.git}).
 *
 * @param connectTimeout TCP/TLS connection timeout
 * @param requestTimeout whole-request timeout
 * @param allowPlainHttp {@code SAYTU_GIT_ALLOW_PLAIN_HTTP}: accept http:// platforms (tokens in clear), isolated networks only
 * @param allowLoopback  {@code SAYTU_GIT_ALLOW_LOOPBACK}: accept 127.0.0.0/8 and ::1, development only
 * @param caBundle       {@code SAYTU_GIT_CA_BUNDLE}: PEM file of an internal CA, added to the JVM trust store
 * @param localReposRoot {@code SAYTU_LOCAL_REPOS_ROOT}: directory allowed for LOCAL connections, unset to disable them
 * @param useSystemProxy honour the standard JVM proxy properties (https.proxyHost, http.nonProxyHosts)
 */
@ConfigurationProperties(prefix = "saytu.git")
public record GitProperties(Duration connectTimeout, Duration requestTimeout, boolean allowPlainHttp,
                            boolean allowLoopback, Path caBundle, Path localReposRoot, boolean useSystemProxy) {

    public GitProperties {
        connectTimeout = connectTimeout == null ? Duration.ofSeconds(10) : connectTimeout;
        requestTimeout = requestTimeout == null ? Duration.ofSeconds(30) : requestTimeout;
        // An empty environment variable must mean "not configured", not the current directory.
        caBundle = blankToNull(caBundle);
        localReposRoot = blankToNull(localReposRoot);
    }

    private static Path blankToNull(Path path) {
        return path == null || path.toString().isBlank() ? null : path;
    }
}
