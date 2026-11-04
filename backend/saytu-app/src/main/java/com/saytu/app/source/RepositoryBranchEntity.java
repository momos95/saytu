package com.saytu.app.source;

import com.saytu.core.git.BranchNames;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** Branch explicitly configured for scanning (branch_mode = CUSTOM), plus last-scan bookkeeping. */
@Entity
@Table(name = "repository_branch")
public class RepositoryBranchEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "repository_id", nullable = false)
    private SourceRepositoryEntity repository;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "last_scanned_commit", length = 64)
    private String lastScannedCommit;

    @Column(name = "last_scanned_at")
    private Instant lastScannedAt;

    protected RepositoryBranchEntity() {
        // JPA
    }

    public RepositoryBranchEntity(SourceRepositoryEntity repository, String name) {
        this.repository = repository;
        this.name = BranchNames.require(name);
    }

    public void recordScan(String commitSha, Instant at) {
        this.lastScannedCommit = commitSha;
        this.lastScannedAt = at;
    }

    public UUID getId() {
        return id;
    }

    public SourceRepositoryEntity getRepository() {
        return repository;
    }

    public String getName() {
        return name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getLastScannedCommit() {
        return lastScannedCommit;
    }

    public Instant getLastScannedAt() {
        return lastScannedAt;
    }
}
