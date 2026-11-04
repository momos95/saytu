package com.saytu.app.source;

import com.saytu.app.audit.AuditService;
import com.saytu.app.source.SourceRepositoryEntity.BranchMode;
import com.saytu.app.source.SourceViews.NamespaceView;
import com.saytu.app.source.SourceViews.PageView;
import com.saytu.app.source.SourceViews.RemoteBranchView;
import com.saytu.app.source.SourceViews.RemoteBranchesView;
import com.saytu.app.source.SourceViews.RepositoryView;
import com.saytu.app.source.SourceViews.ScanTargetSummary;
import com.saytu.app.vault.TokenVault;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.git.BranchNames;
import com.saytu.core.git.GitProvider.RemoteBranch;
import com.saytu.git.provider.GitProviders;
import com.saytu.git.provider.PageCollector;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * What is audited: selection of namespaces and repositories, and branches to scan.
 * <p>
 * A repository is a scan target when its namespace is selected and either the namespace includes all
 * its repositories (current and future) or the repository itself is selected. Archived repositories
 * and items removed from the platform are never targets.
 */
@Service
public class SelectionService {

    static final int MAX_PAGE_SIZE = 200;
    static final int MAX_REMOTE_BRANCHES = 2_000;

    private final GitConnectionRepository connections;
    private final GitNamespaceRepository namespaces;
    private final SourceRepositoryRepository repositories;
    private final RepositoryBranchRepository branches;
    private final TokenVault vault;
    private final GitProviders providers;
    private final AuditService audit;
    private final TransactionTemplate tx;

    public SelectionService(GitConnectionRepository connections, GitNamespaceRepository namespaces,
                            SourceRepositoryRepository repositories, RepositoryBranchRepository branches,
                            TokenVault vault, GitProviders providers, AuditService audit, TransactionTemplate tx) {
        this.connections = connections;
        this.namespaces = namespaces;
        this.repositories = repositories;
        this.branches = branches;
        this.vault = vault;
        this.providers = providers;
        this.audit = audit;
        this.tx = tx;
    }

    // ------------------------------------------------------------------ reads

    @Transactional(readOnly = true)
    public List<NamespaceView> namespaces(UUID connectionId) {
        if (!connections.existsById(connectionId)) {
            throw new ResourceNotFoundException("Git connection " + connectionId + " not found");
        }
        Map<UUID, long[]> counts = new HashMap<>();
        for (Object[] row : repositories.countsByNamespace(connectionId)) {
            counts.put((UUID) row[0], new long[]{((Number) row[1]).longValue(), row[2] == null ? 0 : ((Number) row[2]).longValue()});
        }
        return namespaces.findByConnectionIdOrderByFullPath(connectionId).stream()
                .map(n -> {
                    long[] c = counts.getOrDefault(n.getId(), new long[]{0, 0});
                    return NamespaceView.of(n, c[0], c[1]);
                })
                .toList();
    }

    @Transactional(readOnly = true)
    public PageView<RepositoryView> repositoriesOf(UUID namespaceId, String query, Boolean selected, int page, int size) {
        if (!namespaces.existsById(namespaceId)) {
            throw new ResourceNotFoundException("Namespace " + namespaceId + " not found");
        }
        Specification<SourceRepositoryEntity> spec = RepositorySpecs.inNamespace(namespaceId).and(RepositorySpecs.notRemoved());
        if (query != null && !query.isBlank()) {
            spec = spec.and(RepositorySpecs.nameContains(query));
        }
        if (selected != null) {
            spec = spec.and(RepositorySpecs.selected(selected));
        }
        return toPage(repositories.findAll(spec, pageRequest(page, size)));
    }

    /** Current scan targets, for the branches configuration page. */
    @Transactional(readOnly = true)
    public PageView<RepositoryView> scanTargets(String query, int page, int size) {
        Specification<SourceRepositoryEntity> spec = RepositorySpecs.scanTarget();
        if (query != null && !query.isBlank()) {
            spec = spec.and(RepositorySpecs.nameContains(query));
        }
        return toPage(repositories.findAll(spec, pageRequest(page, size)));
    }

    @Transactional(readOnly = true)
    public RepositoryView repository(UUID id) {
        SourceRepositoryEntity r = findRepository(id);
        return RepositoryView.of(r, branchNames(r));
    }

    @Transactional(readOnly = true)
    public ScanTargetSummary summary() {
        long def = 0;
        long preset = 0;
        long custom = 0;
        for (Object[] row : repositories.scanTargetCountsByBranchMode()) {
            long n = ((Number) row[1]).longValue();
            switch ((BranchMode) row[0]) {
                case DEFAULT -> def = n;
                case PRESET -> preset = n;
                case CUSTOM -> custom = n;
            }
        }
        return new ScanTargetSummary(namespaces.countActiveSelected(), def + preset + custom, def, preset, custom);
    }

    // ------------------------------------------------------------------ selection

    @Transactional
    public NamespaceView selectNamespace(UUID namespaceId, boolean selected, boolean includeAll) {
        GitNamespaceEntity n = namespaces.findById(namespaceId)
                .orElseThrow(() -> new ResourceNotFoundException("Namespace " + namespaceId + " not found"));
        n.setSelected(selected);
        n.setIncludeAllRepositories(selected && includeAll);
        audit.record("GIT_NAMESPACE_SELECTION", "git_namespace", namespaceId.toString(),
                Map.of("selected", selected, "includeAllRepositories", n.isIncludeAllRepositories()));
        return NamespaceView.of(n, 0, 0);
    }

    /** Selecting a repository also selects its namespace, otherwise the choice would have no effect. */
    @Transactional
    public int selectRepositories(List<UUID> ids, boolean selected) {
        List<SourceRepositoryEntity> found = repositories.findAllById(new LinkedHashSet<>(ids));
        for (SourceRepositoryEntity r : found) {
            r.setSelected(selected);
            if (selected && r.getNamespace() != null && !r.getNamespace().isSelected()) {
                r.getNamespace().setSelected(true);
            }
        }
        audit.record("GIT_REPOSITORY_SELECTION", "source_repository", null,
                Map.of("count", found.size(), "selected", selected));
        return found.size();
    }

    @Transactional
    public int setBranchMode(List<UUID> ids, BranchMode mode) {
        List<SourceRepositoryEntity> found = repositories.findAllById(new LinkedHashSet<>(ids));
        for (SourceRepositoryEntity r : found) {
            r.setBranchMode(mode);
            // CUSTOM without any branch would scan nothing: start from the default branch.
            if (mode == BranchMode.CUSTOM && r.getDefaultBranch() != null
                    && branches.findByRepositoryIdOrderByName(r.getId()).isEmpty()) {
                branches.save(new RepositoryBranchEntity(r, r.getDefaultBranch()));
            }
        }
        audit.record("GIT_BRANCH_MODE", "source_repository", null, Map.of("count", found.size(), "mode", mode.name()));
        return found.size();
    }

    /** Replaces the custom branch list (switches the repository to CUSTOM). Branch names follow git rules. */
    @Transactional
    public RepositoryView setCustomBranches(UUID repositoryId, List<String> names) {
        SourceRepositoryEntity r = findRepository(repositoryId);
        Set<String> wanted = new LinkedHashSet<>();
        for (String name : names) {
            wanted.add(BranchNames.require(name.strip()));
        }
        if (wanted.isEmpty()) {
            throw new IllegalArgumentException("Give at least one branch, or choose another branch mode");
        }
        List<RepositoryBranchEntity> current = branches.findByRepositoryIdOrderByName(repositoryId);
        Set<String> kept = new LinkedHashSet<>();
        for (RepositoryBranchEntity b : current) {
            if (wanted.contains(b.getName())) {
                kept.add(b.getName()); // keeps last scanned commit
            } else {
                branches.delete(b);
            }
        }
        branches.flush();
        for (String name : wanted) {
            if (!kept.contains(name)) {
                branches.save(new RepositoryBranchEntity(r, name));
            }
        }
        r.setBranchMode(BranchMode.CUSTOM);
        audit.record("GIT_CUSTOM_BRANCHES", "source_repository", repositoryId.toString(),
                Map.of("branches", List.copyOf(wanted)));
        return RepositoryView.of(r, List.copyOf(wanted));
    }

    /** Branches currently on the platform (live call), to help picking the custom list. */
    public RemoteBranchesView remoteBranches(UUID repositoryId) {
        record Target(GitConnectionEntity connection, String externalId, Set<String> configured) {
        }
        Target t = tx.execute(status -> {
            SourceRepositoryEntity r = findRepository(repositoryId);
            GitConnectionEntity c = r.getConnection();
            c.getName(); // initialise
            return new Target(c, r.getExternalId(), new LinkedHashSet<>(branchNames(r)));
        });
        PageCollector.Result<RemoteBranch> fetched;
        try (OpenConnection c = OpenConnection.open(t.connection(), vault, providers)) {
            fetched = PageCollector.collect(page -> c.provider().listBranches(c.spec(), t.externalId(), page),
                    MAX_REMOTE_BRANCHES);
        }
        String defaultBranch = fetched.items().stream().filter(RemoteBranch::isDefault).map(RemoteBranch::name)
                .findFirst().orElse(null);
        if (defaultBranch != null) {
            // Bitbucket Data Center only reveals the default branch here
            tx.executeWithoutResult(status -> repositories.findById(repositoryId).ifPresent(r -> {
                if (r.getDefaultBranch() == null) {
                    r.setDefaultBranch(defaultBranch);
                }
            }));
        }
        List<RemoteBranchView> views = new ArrayList<>();
        for (RemoteBranch b : fetched.items()) {
            views.add(new RemoteBranchView(b.name(), b.headCommitSha(), b.isDefault(), b.isProtected(),
                    t.configured().contains(b.name())));
        }
        String status = fetched.error() != null ? fetched.error().kind().name() : fetched.truncated() ? "PARTIAL" : "OK";
        return new RemoteBranchesView(views, fetched.truncated(), status,
                fetched.error() != null ? fetched.error().getMessage() : null);
    }

    // ------------------------------------------------------------------ helpers

    private SourceRepositoryEntity findRepository(UUID id) {
        return repositories.findById(id).orElseThrow(() -> new ResourceNotFoundException("Repository " + id + " not found"));
    }

    private List<String> branchNames(SourceRepositoryEntity r) {
        return branches.findByRepositoryIdOrderByName(r.getId()).stream().map(RepositoryBranchEntity::getName).toList();
    }

    private PageView<RepositoryView> toPage(Page<SourceRepositoryEntity> page) {
        Map<UUID, List<String>> custom = new HashMap<>();
        List<UUID> customIds = page.getContent().stream().filter(r -> r.getBranchMode() == BranchMode.CUSTOM)
                .map(SourceRepositoryEntity::getId).toList();
        if (!customIds.isEmpty()) {
            custom = branches.findByRepositoryIdIn(customIds).stream().collect(Collectors.groupingBy(
                    b -> b.getRepository().getId(), Collectors.mapping(RepositoryBranchEntity::getName, Collectors.toList())));
        }
        Map<UUID, List<String>> finalCustom = custom;
        List<RepositoryView> items = page.getContent().stream()
                .map(r -> RepositoryView.of(r, finalCustom.getOrDefault(r.getId(), List.of()).stream().sorted().toList()))
                .toList();
        return new PageView<>(items, page.getNumber(), page.getSize(), page.getTotalElements(), page.getTotalPages());
    }

    static PageRequest pageRequest(int page, int size) {
        int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        return PageRequest.of(Math.max(page, 0), safeSize, Sort.by("fullName"));
    }
}
