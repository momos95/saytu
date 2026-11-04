package com.africodeshield.app.source;

import com.africodeshield.app.audit.AuditService;
import com.africodeshield.app.source.SourceViews.DiscoveryResult;
import com.africodeshield.app.source.SourceViews.NamespaceView;
import com.africodeshield.app.vault.TokenVault;
import com.africodeshield.app.web.ConflictException;
import com.africodeshield.app.web.ResourceNotFoundException;
import com.africodeshield.core.git.GitProvider.Namespace;
import com.africodeshield.core.git.GitProvider.RemoteRepository;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.git.provider.GitProviders;
import com.africodeshield.git.provider.PageCollector;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Synchronises what a Git platform exposes (namespaces, repositories) into the database.
 * <p>
 * Remote calls happen outside any database transaction (they can take minutes on large instances);
 * results are then merged in one short transaction. Items no longer returned are flagged
 * {@code removed}, and only after a complete listing: a rate limit or a truncated listing never makes
 * repositories disappear. Selections are preserved across synchronisations.
 */
@Service
public class DiscoveryService {

    /** Upper bound per synchronisation (namespaces of a connection, repositories of a namespace). */
    static final int MAX_ITEMS = 10_000;

    private final GitConnectionRepository connections;
    private final GitNamespaceRepository namespaces;
    private final SourceRepositoryRepository repositories;
    private final TokenVault vault;
    private final GitProviders providers;
    private final AuditService audit;
    private final TransactionTemplate tx;
    private final Clock clock;
    /** One synchronisation at a time per connection (single API instance in the MVP). */
    private final Set<UUID> running = ConcurrentHashMap.newKeySet();

    public DiscoveryService(GitConnectionRepository connections, GitNamespaceRepository namespaces,
                            SourceRepositoryRepository repositories, TokenVault vault, GitProviders providers,
                            AuditService audit, TransactionTemplate tx, Clock clock) {
        this.connections = connections;
        this.namespaces = namespaces;
        this.repositories = repositories;
        this.vault = vault;
        this.providers = providers;
        this.audit = audit;
        this.tx = tx;
        this.clock = clock;
    }

    /** Lists every namespace visible to the connection and merges them. */
    public DiscoveryResult syncNamespaces(UUID connectionId) {
        return exclusive(connectionId, () -> {
            PageCollector.Result<Namespace> fetched;
            try (OpenConnection c = open(connectionId)) {
                fetched = PageCollector.collect(page -> c.provider().listNamespaces(c.spec(), page), MAX_ITEMS);
            }
            return tx.execute(status -> mergeNamespaces(connectionId, fetched));
        });
    }

    /** Adds one namespace by path or slug (public organisation, Bitbucket workspace of an access token...). */
    public NamespaceView addNamespace(UUID connectionId, String path) {
        Optional<Namespace> found;
        try (OpenConnection c = open(connectionId)) {
            found = c.provider().findNamespace(c.spec(), path);
        } catch (GitProviderException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
        Namespace ns = found.orElseThrow(() -> new ResourceNotFoundException(
                "'" + path.strip() + "' was not found or is not visible with this connection's credentials"));
        return tx.execute(status -> {
            GitConnectionEntity connection = connections.findById(connectionId).orElseThrow();
            GitNamespaceEntity entity = namespaces.findByConnectionIdAndExternalId(connectionId, ns.externalId())
                    .orElseGet(() -> new GitNamespaceEntity(connection, ns.externalId(), ns.kind(), ns.fullPath(), ns.name()));
            entity.update(ns.kind(), ns.fullPath(), ns.name(), ns.webUrl() == null ? null : ns.webUrl().toString());
            entity.setAddedManually(true);
            entity.markSeen(clock.instant());
            entity = namespaces.save(entity);
            audit.record("GIT_NAMESPACE_ADDED", "git_namespace", entity.getId().toString(),
                    Map.of("path", ns.fullPath(), "connectionId", connectionId.toString()));
            return NamespaceView.of(entity, 0, 0);
        });
    }

    /** Lists every repository of one namespace and merges them. */
    public DiscoveryResult syncRepositories(UUID namespaceId) {
        GitNamespaceEntity namespace = tx.execute(status -> namespaces.findById(namespaceId)
                .map(n -> {
                    n.getConnection().getId(); // initialise within the transaction
                    return n;
                })
                .orElseThrow(() -> new ResourceNotFoundException("Namespace " + namespaceId + " not found")));
        UUID connectionId = namespace.getConnection().getId();
        String externalId = namespace.getExternalId();
        return exclusive(connectionId, () -> {
            PageCollector.Result<RemoteRepository> fetched;
            try (OpenConnection c = open(connectionId)) {
                fetched = PageCollector.collect(page -> c.provider().listRepositories(c.spec(), externalId, page), MAX_ITEMS);
            }
            return tx.execute(status -> mergeRepositories(namespaceId, fetched));
        });
    }

    // ------------------------------------------------------------------ merges (inside a transaction)

    DiscoveryResult mergeNamespaces(UUID connectionId, PageCollector.Result<Namespace> fetched) {
        Instant now = clock.instant();
        GitConnectionEntity connection = connections.findById(connectionId).orElseThrow();
        Map<String, GitNamespaceEntity> existing = index(namespaces.findByConnectionId(connectionId),
                GitNamespaceEntity::getExternalId);
        Map<String, GitNamespaceEntity> byExternalId = new HashMap<>(existing);
        Set<String> seen = new HashSet<>();
        int added = 0;
        for (Namespace ns : fetched.items()) {
            if (!seen.add(ns.externalId())) {
                continue;
            }
            GitNamespaceEntity e = existing.get(ns.externalId());
            if (e == null) {
                e = new GitNamespaceEntity(connection, ns.externalId(), ns.kind(), ns.fullPath(), ns.name());
                added++;
            }
            e.update(ns.kind(), ns.fullPath(), ns.name(), ns.webUrl() == null ? null : ns.webUrl().toString());
            e.markSeen(now);
            byExternalId.put(ns.externalId(), namespaces.save(e));
        }
        for (Namespace ns : fetched.items()) {
            GitNamespaceEntity e = byExternalId.get(ns.externalId());
            e.setParent(ns.parentExternalId() == null ? null : byExternalId.get(ns.parentExternalId()));
        }
        int removed = 0;
        if (fetched.complete()) {
            for (GitNamespaceEntity e : existing.values()) {
                if (!seen.contains(e.getExternalId()) && !e.isAddedManually() && !e.isRemoved()) {
                    e.markRemoved(now);
                    removed++;
                }
            }
        }
        DiscoveryResult result = DiscoveryResult.of(seen.size(), added, removed, fetched.truncated(), fetched.error());
        connection.recordDiscovery(result.status(), result.message(), now);
        audit.record("GIT_NAMESPACES_SYNCED", "git_connection", connectionId.toString(),
                Map.of("status", result.status(), "found", result.found(), "added", added, "removed", removed));
        return result;
    }

    DiscoveryResult mergeRepositories(UUID namespaceId, PageCollector.Result<RemoteRepository> fetched) {
        Instant now = clock.instant();
        GitNamespaceEntity namespace = namespaces.findById(namespaceId).orElseThrow();
        GitConnectionEntity connection = namespace.getConnection();
        Map<String, SourceRepositoryEntity> inNamespace = index(repositories.findByNamespaceId(namespaceId),
                SourceRepositoryEntity::getExternalId);
        Set<String> seen = new HashSet<>();
        int added = 0;
        for (RemoteRepository r : fetched.items()) {
            if (!seen.add(r.externalId())) {
                continue;
            }
            SourceRepositoryEntity e = inNamespace.get(r.externalId());
            if (e == null) {
                // may exist under another namespace (transferred repository)
                e = repositories.findByConnectionIdAndExternalId(connection.getId(), r.externalId()).orElse(null);
            }
            if (e == null) {
                e = new SourceRepositoryEntity(connection, r.externalId(), r.fullName(), r.name(), r.cloneUrl().toString());
                added++;
            }
            e.setNamespace(namespace);
            e.setFullName(r.fullName());
            e.setName(r.name());
            e.setCloneUrl(r.cloneUrl().toString());
            e.setWebUrl(r.webUrl() == null ? null : r.webUrl().toString());
            if (r.defaultBranch() != null) {
                e.setDefaultBranch(r.defaultBranch());
            }
            e.setVisibility(r.visibility());
            e.setArchived(r.archived());
            e.setLastActivityAt(r.lastActivityAt());
            e.markSeen(now);
            repositories.save(e);
        }
        int removed = 0;
        if (fetched.complete()) {
            for (SourceRepositoryEntity e : inNamespace.values()) {
                if (!seen.contains(e.getExternalId()) && !e.isRemoved()) {
                    e.markRemoved(now);
                    removed++;
                }
            }
        }
        DiscoveryResult result = DiscoveryResult.of(seen.size(), added, removed, fetched.truncated(), fetched.error());
        namespace.recordRepositorySync(result.status(), result.message(), fetched.truncated(), now);
        audit.record("GIT_REPOSITORIES_SYNCED", "git_namespace", namespaceId.toString(),
                Map.of("status", result.status(), "found", result.found(), "added", added, "removed", removed));
        return result;
    }

    // ------------------------------------------------------------------ helpers

    private OpenConnection open(UUID connectionId) {
        GitConnectionEntity entity = tx.execute(status -> connections.findById(connectionId)
                .orElseThrow(() -> new ResourceNotFoundException("Git connection " + connectionId + " not found")));
        return OpenConnection.open(entity, vault, providers);
    }

    private <T> T exclusive(UUID connectionId, Supplier<T> action) {
        if (!running.add(connectionId)) {
            throw new ConflictException("A synchronisation is already running for this connection; try again shortly");
        }
        try {
            return action.get();
        } finally {
            running.remove(connectionId);
        }
    }

    private static <T> Map<String, T> index(List<T> items, Function<T, String> key) {
        Map<String, T> map = new HashMap<>();
        for (T item : items) {
            map.put(key.apply(item), item);
        }
        return map;
    }
}
