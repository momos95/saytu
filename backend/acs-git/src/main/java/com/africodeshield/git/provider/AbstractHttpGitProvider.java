package com.africodeshield.git.provider;

import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProvider;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.git.http.Auth;
import com.africodeshield.git.http.GitHttpClient;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Shared behaviour of the HTTP-based providers: request plumbing, common warnings and the
 * "never throw from testConnection" contract.
 */
abstract class AbstractHttpGitProvider implements GitProvider {

    /** A token expiring within this window produces a warning. */
    static final Duration EXPIRY_WARNING = Duration.ofDays(14);
    static final String DISCOVERY_PHASE = "Discovery of namespaces, repositories and branches is delivered in phase 3";

    protected final GitHttpClient http;
    protected final Clock clock;

    AbstractHttpGitProvider(GitHttpClient http) {
        this.http = Objects.requireNonNull(http, "http");
        this.clock = http.clock();
    }

    @Override
    public final ConnectionTestResult testConnection(GitConnectionSpec connection) {
        if (connection.providerType() != type()) {
            throw new IllegalArgumentException("Connection of type " + connection.providerType()
                    + " given to the " + type() + " provider");
        }
        List<String> warnings = new ArrayList<>();
        try {
            URI api = ProviderEndpoints.apiBase(connection);
            if ("http".equalsIgnoreCase(api.getScheme())) {
                warnings.add("Plain HTTP: the token travels unencrypted. Use HTTPS outside an isolated network.");
            }
            return doTest(connection, api, warnings);
        } catch (GitProviderException e) {
            return ConnectionTestResult.failure(e, warnings);
        } catch (IllegalArgumentException e) {
            return ConnectionTestResult.failure(
                    new GitProviderException(GitProviderException.Kind.UNEXPECTED_RESPONSE, e.getMessage()), warnings);
        }
    }

    /** Performs the checks; may throw {@link GitProviderException}. {@code warnings} is mutable. */
    protected abstract ConnectionTestResult doTest(GitConnectionSpec connection, URI api, List<String> warnings);

    @Override
    public Page<Namespace> listNamespaces(GitConnectionSpec connection, PageRequest page) {
        throw new UnsupportedOperationException(DISCOVERY_PHASE);
    }

    @Override
    public Page<RemoteRepository> listRepositories(GitConnectionSpec connection, String namespaceExternalId,
                                                   PageRequest page) {
        throw new UnsupportedOperationException(DISCOVERY_PHASE);
    }

    @Override
    public Page<RemoteBranch> listBranches(GitConnectionSpec connection, String repositoryExternalId,
                                           PageRequest page) {
        throw new UnsupportedOperationException(DISCOVERY_PHASE);
    }

    @Override
    public Optional<String> resolveHeadCommit(GitConnectionSpec connection, String repositoryExternalId,
                                              String branch) {
        throw new UnsupportedOperationException(DISCOVERY_PHASE);
    }

    protected static void anonymousWarning(List<String> warnings) {
        warnings.add("Anonymous access: only public repositories will be visible, with the platform's low rate limit.");
    }

    protected void expiryWarning(Instant expiresAt, List<String> warnings) {
        if (expiresAt == null) {
            return;
        }
        Duration left = Duration.between(clock.instant(), expiresAt);
        String date = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC).format(expiresAt);
        if (left.isNegative()) {
            warnings.add("Token expired on " + date + ".");
        } else if (left.compareTo(EXPIRY_WARNING) <= 0) {
            long days = left.toDays();
            warnings.add("Token expires " + (days == 0 ? "today" : "in " + days + " day" + (days > 1 ? "s" : ""))
                    + " (" + date + "): renew it to avoid failed scans.");
        }
    }

    protected static Auth anonymousOr(GitConnectionSpec spec, java.util.function.Supplier<Auth> authenticated) {
        return spec.hasToken() ? authenticated.get() : Auth.none();
    }
}
