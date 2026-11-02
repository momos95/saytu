package com.africodeshield.app.source;

import com.africodeshield.core.domain.GitProviderType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

/**
 * A registered Git platform (GitLab, GitHub, Bitbucket, local directory).
 * The token is stored only as AES-256-GCM ciphertext; decryption happens in the token vault
 * (phase 2) right before an API call or a clone, never in entities or DTOs.
 */
@Entity
@Table(name = "git_connection")
public class GitConnectionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 120)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider_type", nullable = false, length = 32)
    private GitProviderType providerType;

    @Column(name = "base_url", nullable = false, length = 2048)
    private String baseUrl;

    @Column(name = "api_url", length = 2048)
    private String apiUrl;

    @Column(length = 255)
    private String username;

    @Column(name = "token_ciphertext")
    private byte[] tokenCiphertext;

    @Column(name = "token_key_id", length = 64)
    private String tokenKeyId;

    @Column(name = "verify_tls", nullable = false)
    private boolean verifyTls = true;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "last_test_status", length = 32)
    private String lastTestStatus;

    @Column(name = "last_test_message", length = 1000)
    private String lastTestMessage;

    @Column(name = "last_tested_at")
    private Instant lastTestedAt;

    @Column(name = "created_by", nullable = false, updatable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    private long version;

    protected GitConnectionEntity() {
        // JPA
    }

    public GitConnectionEntity(String name, GitProviderType providerType, String baseUrl, String createdBy) {
        this.name = name;
        this.providerType = providerType;
        this.baseUrl = baseUrl;
        this.createdBy = createdBy;
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    /** Stores an already-encrypted token together with the id of the key that encrypted it. */
    public void setEncryptedToken(byte[] ciphertext, String keyId) {
        if ((ciphertext == null) != (keyId == null)) {
            throw new IllegalArgumentException("ciphertext and keyId must be set together");
        }
        this.tokenCiphertext = ciphertext == null ? null : ciphertext.clone();
        this.tokenKeyId = keyId;
    }

    public boolean hasToken() {
        return tokenCiphertext != null;
    }

    public void recordTest(String status, String message, Instant at) {
        this.lastTestStatus = status;
        this.lastTestMessage = message;
        this.lastTestedAt = at;
    }

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public GitProviderType getProviderType() {
        return providerType;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public byte[] getTokenCiphertext() {
        return tokenCiphertext == null ? null : tokenCiphertext.clone();
    }

    public String getTokenKeyId() {
        return tokenKeyId;
    }

    public boolean isVerifyTls() {
        return verifyTls;
    }

    public void setVerifyTls(boolean verifyTls) {
        this.verifyTls = verifyTls;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getLastTestStatus() {
        return lastTestStatus;
    }

    public String getLastTestMessage() {
        return lastTestMessage;
    }

    public Instant getLastTestedAt() {
        return lastTestedAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public long getVersion() {
        return version;
    }

    /** Never prints the ciphertext. */
    @Override
    public String toString() {
        return "GitConnection[id=" + id + ", name=" + name + ", provider=" + providerType + ", baseUrl=" + baseUrl
                + ", hasToken=" + hasToken() + "]";
    }
}
