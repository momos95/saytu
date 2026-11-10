package com.saytu.app.source;

import com.saytu.core.git.GitProvider;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** A repository discovered on a connection. Named "Source..." to avoid clashing with Spring's {@code @Repository}. */
@Entity
@Table(name = "source_repository")
public class SourceRepositoryEntity {

    /** Which branches are scanned. */
    public enum BranchMode {
        /** Only the default branch. */
        DEFAULT,
        /** main, master and develop when they exist. */
        PRESET,
        /** The enabled rows of {@code repository_branch}. */
        CUSTOM
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "connection_id", nullable = false)
    private GitConnectionEntity connection;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "namespace_id")
    private GitNamespaceEntity namespace;

    @Column(name = "external_id", nullable = false)
    private String externalId;

    @Column(name = "full_name", nullable = false, length = 1024)
    private String fullName;

    @Column(nullable = false)
    private String name;

    @Column(name = "clone_url", nullable = false, length = 2048)
    private String cloneUrl;

    @Column(name = "web_url", length = 2048)
    private String webUrl;

    @Column(name = "default_branch")
    private String defaultBranch;

    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private GitProvider.Visibility visibility;

    @Column(nullable = false)
    private boolean archived;

    @Column(nullable = false)
    private boolean selected;

    @Enumerated(EnumType.STRING)
    @Column(name = "branch_mode", nullable = false, length = 16)
    private BranchMode branchMode = BranchMode.DEFAULT;

    @Column(name = "last_activity_at")
    private Instant lastActivityAt;

    /** Language labels of the latest analysed branch, written by the scan worker (read-only here). */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "languages", columnDefinition = "jsonb", insertable = false, updatable = false)
    private List<String> languages = new ArrayList<>();

    /** Git flow check (PASS, WARN, FAIL) of the latest audit, written by the scan worker (read-only here). */
    @Column(name = "workflow_status", length = 8, insertable = false, updatable = false)
    private String workflowStatus;

    @Column(name = "discovered_at", nullable = false, updatable = false)
    private Instant discoveredAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "removed_at")
    private Instant removedAt;

    protected SourceRepositoryEntity() {
        // JPA
    }

    public SourceRepositoryEntity(GitConnectionEntity connection, String externalId, String fullName, String name,
                                  String cloneUrl) {
        this.connection = connection;
        this.externalId = externalId;
        this.fullName = fullName;
        this.name = name;
        this.cloneUrl = validCloneUrl(cloneUrl);
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        discoveredAt = now;
        lastSeenAt = now;
    }

    /** Seen again on the platform: no longer flagged as removed. */
    public void markSeen(Instant at) {
        this.lastSeenAt = at;
        this.removedAt = null;
    }

    public void markRemoved(Instant at) {
        if (removedAt == null) {
            removedAt = at;
        }
    }

    public Instant getRemovedAt() {
        return removedAt;
    }

    public boolean isRemoved() {
        return removedAt != null;
    }

    /**
     * Whether the repository is part of the audit scope: its namespace is selected, and either the
     * namespace includes all its repositories or this one was picked; archived and removed ones never are.
     */
    public boolean isScanTarget() {
        return namespace != null && namespace.isSelected() && !namespace.isRemoved() && !archived && removedAt == null
                && connection.isEnabled() && (namespace.isIncludeAllRepositories() || selected);
    }

    public UUID getId() {
        return id;
    }

    public GitConnectionEntity getConnection() {
        return connection;
    }

    public GitNamespaceEntity getNamespace() {
        return namespace;
    }

    public void setNamespace(GitNamespaceEntity namespace) {
        this.namespace = namespace;
    }

    public String getExternalId() {
        return externalId;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCloneUrl() {
        return cloneUrl;
    }

    /** Rejects URLs carrying credentials (also enforced by a database CHECK constraint). */
    public void setCloneUrl(String cloneUrl) {
        this.cloneUrl = validCloneUrl(cloneUrl);
    }

    // Static helper rather than calling the setter from the constructor: entity methods must stay
    // overridable (non-final) so that Hibernate can create lazy-loading proxies.
    private static String validCloneUrl(String cloneUrl) {
        if (cloneUrl == null || cloneUrl.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*@.*")) {
            throw new IllegalArgumentException("clone URL must not be null nor embed credentials");
        }
        return cloneUrl;
    }

    public String getWebUrl() {
        return webUrl;
    }

    public void setWebUrl(String webUrl) {
        this.webUrl = webUrl;
    }

    public String getDefaultBranch() {
        return defaultBranch;
    }

    public void setDefaultBranch(String defaultBranch) {
        this.defaultBranch = defaultBranch;
    }

    public GitProvider.Visibility getVisibility() {
        return visibility;
    }

    public void setVisibility(GitProvider.Visibility visibility) {
        this.visibility = visibility;
    }

    public boolean isArchived() {
        return archived;
    }

    public void setArchived(boolean archived) {
        this.archived = archived;
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    public BranchMode getBranchMode() {
        return branchMode;
    }

    public void setBranchMode(BranchMode branchMode) {
        this.branchMode = branchMode;
    }

    public Instant getLastActivityAt() {
        return lastActivityAt;
    }

    public List<String> getLanguages() {
        return languages == null ? List.of() : List.copyOf(languages);
    }

    public String getWorkflowStatus() {
        return workflowStatus;
    }

    public void setLastActivityAt(Instant lastActivityAt) {
        this.lastActivityAt = lastActivityAt;
    }

    public Instant getDiscoveredAt() {
        return discoveredAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }
}
