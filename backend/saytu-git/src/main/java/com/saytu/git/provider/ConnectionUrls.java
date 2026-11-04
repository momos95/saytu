package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Objects;

/** Validation and normalisation of the URLs typed by an administrator for a Git connection. */
public final class ConnectionUrls {

    private ConnectionUrls() {
    }

    /**
     * Normalises a base URL: default SaaS URL when blank, lower-case scheme and host, no trailing slash,
     * no query or fragment, no embedded credentials.
     *
     * @throws IllegalArgumentException with a message suitable for the UI
     */
    public static URI normalizeBaseUrl(GitProviderType type, String raw) {
        String value = raw == null ? "" : raw.strip();
        if (value.isEmpty()) {
            if (type.defaultBaseUrl() == null) {
                throw new IllegalArgumentException("A URL is required for " + type);
            }
            value = type.defaultBaseUrl();
        }
        return normalize(type, value, "base URL");
    }

    /** Optional explicit API URL; {@code null} or blank means "derive from the base URL". */
    public static URI normalizeApiUrl(GitProviderType type, String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        if (type == GitProviderType.LOCAL) {
            throw new IllegalArgumentException("Local connections have no API URL");
        }
        return normalize(type, raw.strip(), "API URL");
    }

    private static URI normalize(GitProviderType type, String value, String label) {
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid " + label + ": " + e.getReason());
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (type == GitProviderType.LOCAL) {
            if (!scheme.equals("file") && !scheme.isEmpty()) {
                throw new IllegalArgumentException("Local connections take a directory path such as /srv/git/team");
            }
            String path = scheme.isEmpty() ? value : uri.getPath();
            if (path == null || !path.startsWith("/")) {
                throw new IllegalArgumentException("Local path must be absolute, e.g. /srv/git/team");
            }
            return URI.create("file://" + stripSlashes(path.replace("/./", "/")));
        }
        if (!scheme.equals("https") && !scheme.equals("http")) {
            throw new IllegalArgumentException("The " + label + " must start with https://");
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Do not put credentials in the URL: use the token field");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("The " + label + " has no host");
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("The " + label + " must not contain '?' or '#'");
        }
        String path = uri.getRawPath() == null ? "" : stripSlashes(uri.getRawPath());
        String port = uri.getPort() == -1 ? "" : ":" + uri.getPort();
        return URI.create(scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + port + path);
    }

    /**
     * A stored token may only be reused when the destination host is unchanged. Otherwise an
     * administrator session (or an attacker holding one) could redirect the token to another server
     * just by editing the URL: the token must be typed again.
     */
    public static boolean tokenReentryRequired(URI oldBase, URI oldApi, URI newBase, URI newApi) {
        return !Objects.equals(origin(oldBase), origin(newBase))
                || !Objects.equals(origin(oldApi), origin(newApi));
    }

    private static String origin(URI uri) {
        if (uri == null) {
            return null;
        }
        int port = uri.getPort();
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (port == -1) {
            port = scheme.equals("https") ? 443 : scheme.equals("http") ? 80 : -1;
        }
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        return scheme + "://" + host + ":" + port;
    }

    private static String stripSlashes(String path) {
        String p = path.replaceAll("/{2,}", "/");
        while (p.endsWith("/") && p.length() > 1) {
            p = p.substring(0, p.length() - 1);
        }
        return p.equals("/") ? "" : p;
    }
}
