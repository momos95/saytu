package com.saytu.app.git;

import com.saytu.git.http.EndpointPolicy;
import com.saytu.git.http.GitHttpClient;
import com.saytu.git.http.TrustConfig;
import com.saytu.git.provider.GitProviders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.ProxySelector;
import java.time.Clock;

/** Wires the framework-free Git providers of {@code saytu-git} into Spring. */
@Configuration
public class GitIntegrationConfig {

    private static final Logger log = LoggerFactory.getLogger(GitIntegrationConfig.class);

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    GitHttpClient gitHttpClient(GitProperties properties, Clock clock, @Value("${saytu.version:dev}") String version) {
        if (properties.allowPlainHttp()) {
            log.warn("SAYTU_GIT_ALLOW_PLAIN_HTTP=true: tokens may be sent unencrypted to http:// platforms");
        }
        if (properties.allowLoopback()) {
            log.warn("SAYTU_GIT_ALLOW_LOOPBACK=true: loopback destinations are allowed (development only)");
        }
        var settings = new GitHttpClient.Settings(
                properties.connectTimeout(),
                properties.requestTimeout(),
                8 * 1024 * 1024,
                "SAYTU/" + version,
                TrustConfig.create(properties.caBundle()),
                properties.useSystemProxy() ? ProxySelector.getDefault() : null);
        return new GitHttpClient(settings,
                new EndpointPolicy(properties.allowPlainHttp(), properties.allowLoopback(), null), clock);
    }

    @Bean
    GitProviders gitProviders(GitHttpClient http, GitProperties properties) {
        return new GitProviders(http, properties.localReposRoot());
    }
}
