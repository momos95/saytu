package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitProvider;
import com.africodeshield.git.http.GitHttpClient;

import java.nio.file.Path;
import java.util.EnumMap;
import java.util.Map;

/** Registry of every {@link GitProvider}, one per {@link GitProviderType}. */
public final class GitProviders {

    private final Map<GitProviderType, GitProvider> providers;

    public GitProviders(GitHttpClient http, Path localRoot) {
        Map<GitProviderType, GitProvider> map = new EnumMap<>(GitProviderType.class);
        for (GitProvider p : new GitProvider[]{
                new GitLabProvider(http),
                new GitHubProvider(http),
                new BitbucketCloudProvider(http),
                new BitbucketDataCenterProvider(http),
                new LocalGitProvider(localRoot)}) {
            map.put(p.type(), p);
        }
        if (map.size() != GitProviderType.values().length) {
            throw new IllegalStateException("A provider is missing");
        }
        this.providers = Map.copyOf(map);
    }

    public GitProvider get(GitProviderType type) {
        return providers.get(type);
    }
}
