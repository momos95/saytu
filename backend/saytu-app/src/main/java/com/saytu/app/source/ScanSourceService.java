package com.saytu.app.source;

import com.saytu.app.source.SourceRepositoryEntity.BranchMode;
import com.saytu.app.vault.TokenVault;
import com.saytu.core.domain.GitProviderType;
import com.saytu.core.git.BranchNames;
import com.saytu.core.git.GitProvider.RemoteBranch;
import com.saytu.core.git.GitProviderException;
import com.saytu.core.security.SensitiveValue;
import com.saytu.git.provider.GitProviders;
import com.saytu.git.provider.PageCollector;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * What the scan engine needs from the source catalogue: which repositories are targets, which branches
 * to scan, and how to clone them. The only place where the worker obtains a decrypted token.
 */
@Service
public class ScanSourceService {

    static final int MAX_REMOTE_BRANCHES = 2_000;

    private final SourceRepositoryRepository repositories;
    private final RepositoryBranchRepository branches;
    private final TokenVault vault;
    private final GitProviders providers;
    private final TransactionTemplate tx;

    public ScanSourceService(SourceRepositoryRepository repositories, RepositoryBranchRepository branches,
                             TokenVault vault, GitProviders providers, TransactionTemplate tx) {
        this.repositories = repositories;
        this.branches = branches;
        this.vault = vault;
        this.providers = providers;
        this.tx = tx;
    }

    /** Every current scan target (see {@link SourceRepositoryEntity#isScanTarget()}). */
    @Transactional(readOnly = true)
    public List<UUID> allTargetIds() {
        return repositories.findAll(RepositorySpecs.scanTarget(), Sort.by("fullName")).stream()
                .map(SourceRepositoryEntity::getId).toList();
    }

    /** Ids among {@code ids} that are current scan targets. */
    @Transactional(readOnly = true)
    public Set<UUID> targetsAmong(List<UUID> ids) {
        Set<UUID> result = new LinkedHashSet<>();
        for (SourceRepositoryEntity r : repositories.findAllById(ids)) {
            if (r.isScanTarget()) {
                result.add(r.getId());
            }
        }
        return result;
    }

    /**
     * Branches to scan for a repository, according to its branch mode. DEFAULT and CUSTOM are read
     * from the database; PRESET (main / master / develop) keeps only the branches that exist on the
     * platform, which needs a live call, as does DEFAULT when the platform never reported it.
     */
    public BranchPlan branchesToScan(UUID repositoryId) {
        record Loaded(BranchMode mode, String defaultBranch, List<String> custom, GitConnectionEntity connection,
                      String externalId, String fullName) {
        }
        Loaded l = tx.execute(status -> {
            SourceRepositoryEntity r = repositories.findById(repositoryId).orElse(null);
            if (r == null) {
                return null;
            }
            GitConnectionEntity c = r.getConnection();
            c.getName(); // initialise the lazy association inside the transaction
            List<String> custom = branches.findByRepositoryIdAndEnabledTrue(repositoryId).stream()
                    .map(RepositoryBranchEntity::getName).sorted().toList();
            return new Loaded(r.getBranchMode(), r.getDefaultBranch(), custom, c, r.getExternalId(), r.getFullName());
        });
        if (l == null) {
            return new BranchPlan(repositoryId, null, List.of(), "repository no longer exists");
        }
        switch (l.mode()) {
            case CUSTOM -> {
                return new BranchPlan(repositoryId, l.fullName(), l.custom(),
                        l.custom().isEmpty() ? "no custom branch configured" : null);
            }
            case DEFAULT -> {
                if (l.defaultBranch() != null && BranchNames.isValid(l.defaultBranch())) {
                    return new BranchPlan(repositoryId, l.fullName(), List.of(l.defaultBranch()), null);
                }
            }
            case PRESET -> {
                // handled below with the remote list
            }
        }
        List<RemoteBranch> remote;
        try (OpenConnection c = OpenConnection.open(l.connection(), vault, providers)) {
            PageCollector.Result<RemoteBranch> fetched = PageCollector.collect(
                    page -> c.provider().listBranches(c.spec(), l.externalId(), page), MAX_REMOTE_BRANCHES);
            if (fetched.error() != null && fetched.items().isEmpty()) {
                return new BranchPlan(repositoryId, l.fullName(), List.of(), describe(fetched.error()));
            }
            remote = fetched.items();
        } catch (GitProviderException e) {
            return new BranchPlan(repositoryId, l.fullName(), List.of(), describe(e));
        } catch (RuntimeException e) {
            return new BranchPlan(repositoryId, l.fullName(), List.of(), "branches could not be listed: " + e.getMessage());
        }
        if (l.mode() == BranchMode.DEFAULT) {
            Optional<String> def = remote.stream().filter(RemoteBranch::isDefault).map(RemoteBranch::name).findFirst();
            return def.map(d -> new BranchPlan(repositoryId, l.fullName(), List.of(d), null))
                    .orElseGet(() -> new BranchPlan(repositoryId, l.fullName(), List.of(), "default branch unknown"));
        }
        Set<String> existing = new LinkedHashSet<>();
        remote.forEach(b -> existing.add(b.name()));
        List<String> preset = new ArrayList<>();
        for (String name : BranchNames.PRESET) {
            if (existing.contains(name)) {
                preset.add(name);
            }
        }
        return new BranchPlan(repositoryId, l.fullName(), preset,
                preset.isEmpty() ? "none of main, master, develop exists" : null);
    }

    private static String describe(GitProviderException e) {
        return e.kind() + ": " + e.getMessage();
    }

    /**
     * Opens what the worker needs to clone a repository. The token is decrypted here and must be
     * wiped by closing the result as soon as the clone is done.
     */
    @Transactional(readOnly = true)
    public CloneSource openCloneSource(UUID repositoryId) {
        SourceRepositoryEntity r = repositories.findById(repositoryId)
                .orElseThrow(() -> new IllegalStateException("repository " + repositoryId + " no longer exists"));
        GitConnectionEntity c = r.getConnection();
        if (!c.isEnabled()) {
            throw new IllegalStateException("connection '" + c.getName() + "' is disabled");
        }
        SensitiveValue token = c.hasToken() && c.getProviderType() != GitProviderType.LOCAL
                ? vault.decrypt(c.getTokenCiphertext(), c.getTokenKeyId(),
                TokenVault.owner(GitConnectionService.OWNER_TABLE, c.getId()))
                : null;
        return new CloneSource(r.getFullName(), URI.create(r.getCloneUrl()), c.getProviderType(), c.getUsername(), token);
    }

    /**
     * @param problem why no branch can be scanned, {@code null} when {@code branches} is not empty
     */
    public record BranchPlan(UUID repositoryId, String fullName, List<String> branches, String problem) {
        public BranchPlan {
            branches = List.copyOf(branches);
        }
    }

    /** Clone parameters; {@link #close()} wipes the token. */
    public record CloneSource(String fullName, URI cloneUrl, GitProviderType providerType, String username,
                              SensitiveValue token) implements AutoCloseable {
        @Override
        public void close() {
            if (token != null) {
                token.destroy();
            }
        }

        @Override
        public String toString() {
            return "CloneSource[" + fullName + ", " + cloneUrl + ", " + providerType + ", token="
                    + (token == null ? "none" : SensitiveValue.MASK) + "]";
        }
    }
}
