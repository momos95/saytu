package com.saytu.app.source;

import com.saytu.core.domain.NamespaceKind;
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

import java.time.Instant;
import java.util.UUID;

/** Organisation, group, sub-group, workspace or project discovered on a connection. */
@Entity
@Table(name = "git_namespace")
public class GitNamespaceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "connection_id", nullable = false)
    private GitConnectionEntity connection;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private GitNamespaceEntity parent;

    @Column(name = "external_id", nullable = false)
    private String externalId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private NamespaceKind kind;

    @Column(name = "full_path", nullable = false, length = 1024)
    private String fullPath;

    @Column(nullable = false)
    private String name;

    @Column(name = "web_url", length = 2048)
    private String webUrl;

    @Column(nullable = false)
    private boolean selected;

    @Column(name = "include_all_repositories", nullable = false)
    private boolean includeAllRepositories;

    @Column(name = "discovered_at", nullable = false, updatable = false)
    private Instant discoveredAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "removed_at")
    private Instant removedAt;

    @Column(name = "added_manually", nullable = false)
    private boolean addedManually;

    @Column(name = "repositories_synced_at")
    private Instant repositoriesSyncedAt;

    @Column(name = "repositories_sync_status", length = 32)
    private String repositoriesSyncStatus;

    @Column(name = "repositories_sync_message", length = 1000)
    private String repositoriesSyncMessage;

    @Column(name = "repositories_truncated", nullable = false)
    private boolean repositoriesTruncated;

    protected GitNamespaceEntity() {
        // JPA
    }

    public GitNamespaceEntity(GitConnectionEntity connection, String externalId, NamespaceKind kind,
                              String fullPath, String name) {
        this.connection = connection;
        this.externalId = externalId;
        this.kind = kind;
        this.fullPath = fullPath;
        this.name = name;
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

    public void update(NamespaceKind kind, String fullPath, String name, String webUrl) {
        this.kind = kind;
        this.fullPath = fullPath;
        this.name = name;
        this.webUrl = webUrl;
    }

    public void recordRepositorySync(String status, String message, boolean truncated, Instant at) {
        this.repositoriesSyncStatus = status;
        this.repositoriesSyncMessage = message == null || message.length() <= 1000 ? message : message.substring(0, 999) + "…";
        this.repositoriesTruncated = truncated;
        this.repositoriesSyncedAt = at;
    }

    public Instant getRemovedAt() {
        return removedAt;
    }

    public boolean isRemoved() {
        return removedAt != null;
    }

    public boolean isAddedManually() {
        return addedManually;
    }

    public void setAddedManually(boolean addedManually) {
        this.addedManually = addedManually;
    }

    public Instant getRepositoriesSyncedAt() {
        return repositoriesSyncedAt;
    }

    public String getRepositoriesSyncStatus() {
        return repositoriesSyncStatus;
    }

    public String getRepositoriesSyncMessage() {
        return repositoriesSyncMessage;
    }

    public boolean isRepositoriesTruncated() {
        return repositoriesTruncated;
    }

    public UUID getId() {
        return id;
    }

    public GitConnectionEntity getConnection() {
        return connection;
    }

    public GitNamespaceEntity getParent() {
        return parent;
    }

    public void setParent(GitNamespaceEntity parent) {
        this.parent = parent;
    }

    public String getExternalId() {
        return externalId;
    }

    public NamespaceKind getKind() {
        return kind;
    }

    public String getFullPath() {
        return fullPath;
    }

    public void setFullPath(String fullPath) {
        this.fullPath = fullPath;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getWebUrl() {
        return webUrl;
    }

    public void setWebUrl(String webUrl) {
        this.webUrl = webUrl;
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    public boolean isIncludeAllRepositories() {
        return includeAllRepositories;
    }

    public void setIncludeAllRepositories(boolean includeAllRepositories) {
        this.includeAllRepositories = includeAllRepositories;
    }

    public Instant getDiscoveredAt() {
        return discoveredAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }
}
