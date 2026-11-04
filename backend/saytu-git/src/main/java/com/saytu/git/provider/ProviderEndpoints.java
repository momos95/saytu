package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.git.GitConnectionSpec;

import java.net.URI;
import java.util.Locale;

/** Derives the REST API root of each platform from the web URL entered by the user. */
public final class ProviderEndpoints {

    private ProviderEndpoints() {
    }

    public static URI apiBase(GitConnectionSpec spec) {
        if (spec.apiUrl() != null) {
            return stripTrailingSlash(spec.apiUrl());
        }
        URI base = stripTrailingSlash(spec.baseUrl());
        String host = base.getHost() == null ? "" : base.getHost().toLowerCase(Locale.ROOT);
        return switch (spec.providerType()) {
            case GITLAB -> append(base, "/api/v4");
            case GITHUB -> host.equals("github.com") || host.equals("www.github.com")
                    ? URI.create("https://api.github.com")
                    : host.equals("api.github.com") ? base : append(base, "/api/v3");
            case BITBUCKET_CLOUD -> {
                if (host.equals("bitbucket.org") || host.equals("www.bitbucket.org") || host.equals("api.bitbucket.org")) {
                    yield URI.create("https://api.bitbucket.org/2.0");
                }
                throw new IllegalArgumentException("Bitbucket Cloud URL must be https://bitbucket.org; "
                        + "use BITBUCKET_DATA_CENTER for a self-hosted instance");
            }
            case BITBUCKET_DATA_CENTER -> append(base, "/rest/api/1.0");
            case LOCAL -> base;
        };
    }

    /** Appends a path (and optional query) to a base URI, keeping the base path (unlike URI#resolve). */
    public static URI append(URI base, String pathAndQuery) {
        String b = stripTrailingSlash(base).toString();
        String p = pathAndQuery.startsWith("/") ? pathAndQuery : "/" + pathAndQuery;
        return URI.create(b + p);
    }

    static URI stripTrailingSlash(URI uri) {
        String s = uri.toString();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return URI.create(s);
    }

    /** Normalised default URL for SaaS platforms, {@code null} if the type has none. */
    public static String defaultBaseUrl(GitProviderType type) {
        return type.defaultBaseUrl();
    }
}
