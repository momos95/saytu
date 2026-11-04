package com.africodeshield.core.git;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.domain.NamespaceKind;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Port to a Git hosting platform. One implementation per {@link GitProviderType}
 * (GitLab, GitHub, Bitbucket Cloud, Bitbucket Data Center, local directory).
 * <p>
 * Contract:
 * <ul>
 *   <li>implementations are stateless; credentials are passed with each call;</li>
 *   <li>errors are reported as {@link GitProviderException} with a typed {@link GitProviderException.Kind};
 *       messages never contain the token;</li>
 *   <li>listing methods are paginated with an opaque cursor so that offset (GitLab, Bitbucket DC),
 *       Link-header (GitHub) and {@code next} URL (Bitbucket Cloud) pagination share one API;</li>
 *   <li>implementations never clone: cloning is done by the worker (see {@code RepositoryFetcher}).</li>
 * </ul>
 */
public interface GitProvider {

    GitProviderType type();

    /** Checks reachability, credentials and the scopes needed for discovery and cloning. */
    ConnectionTestResult testConnection(GitConnectionSpec connection);

    /** Organisations / groups / sub-groups / workspaces / projects visible to the token. */
    Page<Namespace> listNamespaces(GitConnectionSpec connection, PageRequest page);

    /**
     * Looks up one namespace by its path or slug (e.g. a public GitHub organisation, a Bitbucket
     * workspace reachable only with a workspace access token). Empty when it does not exist or is not
     * visible to the credentials.
     */
    Optional<Namespace> findNamespace(GitConnectionSpec connection, String path);

    /** Repositories of one namespace. */
    Page<RemoteRepository> listRepositories(GitConnectionSpec connection, String namespaceExternalId, PageRequest page);

    /** Branches of one repository. */
    Page<RemoteBranch> listBranches(GitConnectionSpec connection, String repositoryExternalId, PageRequest page);

    /** Resolves the current head commit of a branch, used to skip unchanged branches. */
    Optional<String> resolveHeadCommit(GitConnectionSpec connection, String repositoryExternalId, String branch);

    // ---------------------------------------------------------------- value types

    record PageRequest(String cursor, int size) {
        public static final int MAX_SIZE = 100;

        public PageRequest {
            if (size < 1 || size > MAX_SIZE) {
                throw new IllegalArgumentException("page size must be within [1, " + MAX_SIZE + "]");
            }
        }

        public static PageRequest first(int size) {
            return new PageRequest(null, size);
        }
    }

    /** @param nextCursor {@code null} on the last page */
    record Page<T>(List<T> items, String nextCursor, Integer totalCount) {
        public Page {
            items = List.copyOf(items);
        }

        public boolean hasNext() {
            return nextCursor != null;
        }
    }

    record Namespace(String externalId, NamespaceKind kind, String fullPath, String name, String parentExternalId,
                     URI webUrl) {
    }

    record RemoteRepository(String externalId, String namespaceExternalId, String fullName, String name,
                            URI cloneUrl, URI webUrl, String defaultBranch, Visibility visibility,
                            boolean archived, Instant lastActivityAt) {
    }

    record RemoteBranch(String name, String headCommitSha, boolean isDefault, boolean isProtected) {
    }

    enum Visibility { PUBLIC, INTERNAL, PRIVATE }

    /**
     * @param grantedScopes  scopes reported by the platform when available (GitLab / GitHub classic tokens)
     * @param warnings       non-blocking issues, e.g. "token expires in 5 days", "anonymous access"
     * @param tokenExpiresAt token expiry when the platform reports it, else {@code null}
     */
    record ConnectionTestResult(boolean success, String authenticatedAs, String serverVersion,
                                List<String> grantedScopes, List<String> warnings, Instant tokenExpiresAt,
                                GitProviderException.Kind errorKind, String errorMessage) {

        public ConnectionTestResult {
            grantedScopes = grantedScopes == null ? List.of() : List.copyOf(grantedScopes);
            warnings = warnings == null ? List.of() : List.copyOf(warnings);
        }

        public static ConnectionTestResult ok(String authenticatedAs, String serverVersion,
                                              List<String> scopes, List<String> warnings, Instant tokenExpiresAt) {
            return new ConnectionTestResult(true, authenticatedAs, serverVersion, scopes, warnings, tokenExpiresAt,
                    null, null);
        }

        public static ConnectionTestResult failure(GitProviderException e) {
            return failure(e, List.of());
        }

        /** Failure that still carries what was learnt before the check failed (e.g. scopes, warnings). */
        public static ConnectionTestResult failure(GitProviderException e, List<String> warnings) {
            return new ConnectionTestResult(false, null, null, List.of(), warnings, null, e.kind(), e.getMessage());
        }
    }
}
