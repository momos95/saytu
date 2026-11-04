package com.africodeshield.app.scanner;

import com.africodeshield.core.domain.ScannerId;
import com.africodeshield.core.scan.ResourceLimits;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Global configuration of one scanner (row seeded by the V1 migration). */
@Entity
@Table(name = "scanner_config")
public class ScannerConfigEntity {

    @Id
    @Column(name = "scanner_id", length = 32)
    private String scannerId;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "timeout_seconds", nullable = false)
    private int timeoutSeconds;

    @Column(name = "cpu_seconds", nullable = false)
    private int cpuSeconds;

    @Column(name = "memory_mb", nullable = false)
    private int memoryMb;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> settings = new HashMap<>();

    @Column(name = "updated_by")
    private String updatedBy;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected ScannerConfigEntity() {
        // JPA
    }

    public Optional<ScannerId> scanner() {
        return ScannerId.fromKey(scannerId);
    }

    /** Limits to hand to the sandbox. Output and file-descriptor caps use the platform defaults. */
    public ResourceLimits toResourceLimits() {
        return new ResourceLimits(Duration.ofSeconds(timeoutSeconds), cpuSeconds, memoryMb * 1024L * 1024L,
                ResourceLimits.DEFAULT.maxOutputBytes(), ResourceLimits.DEFAULT.maxOpenFiles());
    }

    /** Bounds mirror the database CHECK constraints of {@code scanner_config}. */
    public void update(boolean enabled, int timeoutSeconds, int cpuSeconds, int memoryMb, String updatedBy, Instant at) {
        if (timeoutSeconds < 30 || timeoutSeconds > 21_600) {
            throw new IllegalArgumentException("timeoutSeconds must be between 30 and 21600");
        }
        if (cpuSeconds < 1 || memoryMb < 64) {
            throw new IllegalArgumentException("cpuSeconds must be >= 1 and memoryMb >= 64");
        }
        this.enabled = enabled;
        this.timeoutSeconds = timeoutSeconds;
        this.cpuSeconds = cpuSeconds;
        this.memoryMb = memoryMb;
        this.updatedBy = updatedBy;
        this.updatedAt = at;
    }

    public String getScannerId() {
        return scannerId;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public int getCpuSeconds() {
        return cpuSeconds;
    }

    public int getMemoryMb() {
        return memoryMb;
    }

    public Map<String, Object> getSettings() {
        return Map.copyOf(settings);
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
