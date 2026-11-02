package com.africodeshield.app.source;

import com.africodeshield.core.domain.NamespaceKind;
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

    public void markSeen(Instant at) {
        this.lastSeenAt = at;
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
