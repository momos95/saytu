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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
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

    @Column(name = "last_test_identity")
    private String lastTestIdentity;

    @Column(name = "last_test_server_version")
    private String lastTestServerVersion;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "last_test_warnings", nullable = false, columnDefinition = "text[]")
    private String[] lastTestWarnings = new String[0];

    @Column(name = "token_expires_at")
    private Instant tokenExpiresAt;

    @Column(name = "last_discovery_at")
    private Instant lastDiscoveryAt;

    @Column(name = "last_discovery_status", length = 32)
    private String lastDiscoveryStatus;

    @Column(name = "last_discovery_message", length = 1000)
    private String lastDiscoveryMessage;

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

    /** Stores the outcome of the latest connection test (never contains the token). */
    public void recordTest(String status, String message, String identity, String serverVersion,
                           List<String> warnings, Instant tokenExpiresAt, Instant at) {
        this.lastTestStatus = status;
        this.lastTestMessage = truncate(message, 1000);
        this.lastTestIdentity = truncate(identity, 255);
        this.lastTestServerVersion = truncate(serverVersion, 255);
        this.lastTestWarnings = warnings == null ? new String[0] : warnings.toArray(String[]::new);
        if (tokenExpiresAt != null || "OK".equals(status)) {
            this.tokenExpiresAt = tokenExpiresAt;
        }
        this.lastTestedAt = at;
    }

    /** A new or removed token invalidates what the previous test learnt. */
    public void clearTestResult() {
        this.lastTestStatus = null;
        this.lastTestMessage = null;
        this.lastTestIdentity = null;
        this.lastTestServerVersion = null;
        this.lastTestWarnings = new String[0];
        this.tokenExpiresAt = null;
        this.lastTestedAt = null;
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max - 1) + "…";
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

    /** TLS verification cannot be disabled (database constraint since V2); trust an internal CA instead. */
    public void setVerifyTls(boolean verifyTls) {
        if (!verifyTls) {
            throw new IllegalArgumentException("TLS verification cannot be disabled; configure ACS_GIT_CA_BUNDLE");
        }
        this.verifyTls = true;
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

    public String getLastTestIdentity() {
        return lastTestIdentity;
    }

    public String getLastTestServerVersion() {
        return lastTestServerVersion;
    }

    public List<String> getLastTestWarnings() {
        return lastTestWarnings == null ? List.of() : List.of(lastTestWarnings);
    }

    public Instant getTokenExpiresAt() {
        return tokenExpiresAt;
    }

    public void recordDiscovery(String status, String message, Instant at) {
        this.lastDiscoveryStatus = status;
        this.lastDiscoveryMessage = truncate(message, 1000);
        this.lastDiscoveryAt = at;
    }

    public Instant getLastDiscoveryAt() {
        return lastDiscoveryAt;
    }

    public String getLastDiscoveryStatus() {
        return lastDiscoveryStatus;
    }

    public String getLastDiscoveryMessage() {
        return lastDiscoveryMessage;
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
