package com.africodeshield.core.domain;

/** Supported Git hosting platforms. SaaS and self-hosted variants share an API family. */
public enum GitProviderType {
    /** gitlab.com and GitLab Self-Managed (REST API v4). */
    GITLAB(true, "https://gitlab.com"),
    /** github.com and GitHub Enterprise Server (REST API v3). */
    GITHUB(true, "https://github.com"),
    /** bitbucket.org (REST API 2.0). */
    BITBUCKET_CLOUD(true, "https://bitbucket.org"),
    /** Bitbucket Data Center / Server (REST API 1.0). */
    BITBUCKET_DATA_CENTER(true, null),
    /** Repositories on a directory mounted read-only into the worker. */
    LOCAL(false, null);

    private final boolean requiresToken;
    private final String defaultBaseUrl;

    GitProviderType(boolean requiresToken, String defaultBaseUrl) {
        this.requiresToken = requiresToken;
        this.defaultBaseUrl = defaultBaseUrl;
    }

    /** Whether a token is mandatory to reach private resources (public ones may work without). */
    public boolean requiresToken() {
        return requiresToken;
    }

    /** SaaS URL, or {@code null} for self-hosted-only providers. */
    public String defaultBaseUrl() {
        return defaultBaseUrl;
    }
}
