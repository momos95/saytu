package com.saytu.app.source;

import com.saytu.core.domain.NamespaceKind;
import com.saytu.core.git.GitProvider.Visibility;
import com.saytu.core.git.GitProviderException;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** DTOs of the "Organisations & dépôts" and "Scanners & branches" pages. */
public final class SourceViews {

    private SourceViews() {
    }

    public record NamespaceView(UUID id, UUID connectionId, String externalId, NamespaceKind kind, String fullPath,
                                String name, UUID parentId, String webUrl, boolean selected,
                                boolean includeAllRepositories, boolean addedManually, boolean removed,
                                Instant repositoriesSyncedAt, String repositoriesSyncStatus,
                                String repositoriesSyncMessage, boolean repositoriesTruncated,
                                long repositoryCount, long selectedRepositoryCount) {

        static NamespaceView of(GitNamespaceEntity n, long repositories, long selectedRepositories) {
            return new NamespaceView(n.getId(), n.getConnection().getId(), n.getExternalId(), n.getKind(),
                    n.getFullPath(), n.getName(), n.getParent() == null ? null : n.getParent().getId(), n.getWebUrl(),
                    n.isSelected(), n.isIncludeAllRepositories(), n.isAddedManually(), n.isRemoved(),
                    n.getRepositoriesSyncedAt(), n.getRepositoriesSyncStatus(), n.getRepositoriesSyncMessage(),
                    n.isRepositoriesTruncated(), repositories, selectedRepositories);
        }
    }

    public record RepositoryView(UUID id, UUID connectionId, String connectionName, UUID namespaceId,
                                 String namespacePath, String fullName, String name, String webUrl,
                                 String defaultBranch, Visibility visibility, boolean archived, boolean removed,
                                 boolean selected, boolean scanTarget, SourceRepositoryEntity.BranchMode branchMode,
                                 List<String> branches, Instant lastActivityAt, List<String> languages) {

        static RepositoryView of(SourceRepositoryEntity r, List<String> branches) {
            GitNamespaceEntity ns = r.getNamespace();
            return new RepositoryView(r.getId(), r.getConnection().getId(), r.getConnection().getName(),
                    ns == null ? null : ns.getId(), ns == null ? null : ns.getFullPath(), r.getFullName(), r.getName(),
                    r.getWebUrl(), r.getDefaultBranch(), r.getVisibility(), r.isArchived(), r.isRemoved(),
                    r.isSelected(), r.isScanTarget(), r.getBranchMode(), branches, r.getLastActivityAt(), r.getLanguages());
        }
    }

    /** Branch on the platform, flagged when it is in the repository's custom list. */
    public record RemoteBranchView(String name, String headCommitSha, boolean isDefault, boolean isProtected,
                                   boolean configured) {
    }

    public record RemoteBranchesView(List<RemoteBranchView> branches, boolean truncated, String status, String message) {
    }

    /**
     * Outcome of a synchronisation.
     *
     * @param status OK, PARTIAL (truncated) or the error kind; partial results are kept
     */
    public record DiscoveryResult(String status, String message, int found, int added, int removed, boolean truncated,
                                  Long retryAfterSeconds) {

        static DiscoveryResult of(int found, int added, int removed, boolean truncated, GitProviderException error) {
            if (error != null) {
                return new DiscoveryResult(error.kind().name(), error.getMessage(), found, added, removed, truncated,
                        error.retryAfter().map(d -> Math.max(1, d.toSeconds())).orElse(null));
            }
            return new DiscoveryResult(truncated ? "PARTIAL" : "OK",
                    truncated ? "Listing stopped after " + found + " items" : null, found, added, removed, truncated, null);
        }
    }

    public record PageView<T>(List<T> items, int page, int size, long totalElements, int totalPages) {
    }

    public record ScanTargetSummary(long selectedNamespaces, long repositories, long defaultBranchMode,
                                    long presetBranchMode, long customBranchMode) {
    }

    // ------------------------------------------------------------------ requests

    public record AddNamespaceRequest(@NotBlank @Size(max = 512) String path) {
    }

    public record NamespaceSelectionRequest(boolean selected, boolean includeAllRepositories) {
    }

    public record RepositorySelectionRequest(@NotEmpty @Size(max = 1000) List<@NotNull UUID> repositoryIds,
                                             boolean selected) {
    }

    public record BranchModeRequest(@NotEmpty @Size(max = 1000) List<@NotNull UUID> repositoryIds,
                                    @NotNull SourceRepositoryEntity.BranchMode mode) {
    }

    public record CustomBranchesRequest(@NotNull @Size(max = 50) List<@NotBlank @Size(max = 255) String> branches) {
    }
}
