package com.africodeshield.app.source;

import com.africodeshield.app.source.SourceViews.AddNamespaceRequest;
import com.africodeshield.app.source.SourceViews.BranchModeRequest;
import com.africodeshield.app.source.SourceViews.CustomBranchesRequest;
import com.africodeshield.app.source.SourceViews.DiscoveryResult;
import com.africodeshield.app.source.SourceViews.NamespaceSelectionRequest;
import com.africodeshield.app.source.SourceViews.NamespaceView;
import com.africodeshield.app.source.SourceViews.PageView;
import com.africodeshield.app.source.SourceViews.RemoteBranchesView;
import com.africodeshield.app.source.SourceViews.RepositorySelectionRequest;
import com.africodeshield.app.source.SourceViews.RepositoryView;
import com.africodeshield.app.source.SourceViews.ScanTargetSummary;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Pages "Organisations & dépôts" and "Scanners & branches". Reading is open to every role;
 * synchronisation, selection and branch configuration are reserved to ADMIN.
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Discovery and selection")
public class DiscoveryController {

    private final DiscoveryService discovery;
    private final SelectionService selection;

    public DiscoveryController(DiscoveryService discovery, SelectionService selection) {
        this.discovery = discovery;
        this.selection = selection;
    }

    // ------------------------------------------------------------------ namespaces

    @GetMapping("/git-connections/{connectionId}/namespaces")
    @Operation(summary = "Namespaces (organisations, groups, workspaces, projects) discovered on a connection")
    public List<NamespaceView> namespaces(@PathVariable UUID connectionId) {
        return selection.namespaces(connectionId);
    }

    @PostMapping("/git-connections/{connectionId}/discovery")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List every namespace visible to the connection and store them")
    public DiscoveryResult discoverNamespaces(@PathVariable UUID connectionId) {
        return discovery.syncNamespaces(connectionId);
    }

    @PostMapping("/git-connections/{connectionId}/namespaces")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Add one namespace by path or slug (public organisation, Bitbucket workspace...)")
    public NamespaceView addNamespace(@PathVariable UUID connectionId, @Valid @RequestBody AddNamespaceRequest request) {
        return discovery.addNamespace(connectionId, request.path());
    }

    @PutMapping("/namespaces/{namespaceId}/selection")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Select a namespace, with all its repositories (including future ones) or a custom list")
    public NamespaceView selectNamespace(@PathVariable UUID namespaceId, @RequestBody NamespaceSelectionRequest request) {
        return selection.selectNamespace(namespaceId, request.selected(), request.includeAllRepositories());
    }

    @PostMapping("/namespaces/{namespaceId}/discovery")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List every repository of the namespace and store them")
    public DiscoveryResult discoverRepositories(@PathVariable UUID namespaceId) {
        return discovery.syncRepositories(namespaceId);
    }

    @GetMapping("/namespaces/{namespaceId}/repositories")
    @Operation(summary = "Repositories of a namespace, paginated")
    public PageView<RepositoryView> repositories(@PathVariable UUID namespaceId,
                                                 @RequestParam(required = false) String q,
                                                 @RequestParam(required = false) Boolean selected,
                                                 @RequestParam(defaultValue = "0") int page,
                                                 @RequestParam(defaultValue = "50") int size) {
        return selection.repositoriesOf(namespaceId, q, selected, page, size);
    }

    // ------------------------------------------------------------------ repositories

    @GetMapping("/repositories/targets")
    @Operation(summary = "Repositories in the audit scope, paginated")
    public PageView<RepositoryView> scanTargets(@RequestParam(required = false) String q,
                                                @RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "50") int size) {
        return selection.scanTargets(q, page, size);
    }

    @GetMapping("/repositories/{repositoryId}")
    @Operation(summary = "One repository with its branch configuration")
    public RepositoryView repository(@PathVariable UUID repositoryId) {
        return selection.repository(repositoryId);
    }

    @PutMapping("/repositories/selection")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Select or unselect repositories")
    public Map<String, Integer> selectRepositories(@Valid @RequestBody RepositorySelectionRequest request) {
        return Map.of("updated", selection.selectRepositories(request.repositoryIds(), request.selected()));
    }

    @PutMapping("/repositories/branch-mode")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Branches to scan: DEFAULT (default branch), PRESET (main/master/develop) or CUSTOM")
    public Map<String, Integer> branchMode(@Valid @RequestBody BranchModeRequest request) {
        return Map.of("updated", selection.setBranchMode(request.repositoryIds(), request.mode()));
    }

    @PutMapping("/repositories/{repositoryId}/branches")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Custom list of branches to scan (git branch name rules apply)")
    public RepositoryView customBranches(@PathVariable UUID repositoryId, @Valid @RequestBody CustomBranchesRequest request) {
        return selection.setCustomBranches(repositoryId, request.branches());
    }

    @GetMapping("/repositories/{repositoryId}/remote-branches")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Branches currently on the platform (live call)")
    public RemoteBranchesView remoteBranches(@PathVariable UUID repositoryId) {
        return selection.remoteBranches(repositoryId);
    }

    @GetMapping("/scan-targets/summary")
    @Operation(summary = "Size of the audit scope")
    public ScanTargetSummary summary() {
        return selection.summary();
    }
}
