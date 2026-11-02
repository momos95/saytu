package com.africodeshield.core.scan;

import java.time.Duration;
import java.util.Objects;

/**
 * Per-process limits applied by the worker's process sandbox to each scanner run.
 *
 * @param timeout        wall-clock limit; the whole process tree is killed when exceeded
 * @param cpuSeconds     RLIMIT_CPU (CPU time, all cores)
 * @param memoryBytes    RLIMIT_AS (address space). JVM-based tools get their -Xmx derived from it.
 * @param maxOutputBytes RLIMIT_FSIZE, caps report files and protects the disk
 * @param maxOpenFiles   RLIMIT_NOFILE
 */
public record ResourceLimits(Duration timeout, long cpuSeconds, long memoryBytes, long maxOutputBytes, int maxOpenFiles) {

    public static final ResourceLimits DEFAULT = new ResourceLimits(
            Duration.ofMinutes(15), 1_800, 2L * 1024 * 1024 * 1024, 512L * 1024 * 1024, 4_096);

    public ResourceLimits {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        if (timeout.compareTo(Duration.ofHours(6)) > 0) {
            throw new IllegalArgumentException("timeout must not exceed 6 hours");
        }
        if (cpuSeconds < 1 || memoryBytes < 64L * 1024 * 1024 || maxOutputBytes < 1024 * 1024 || maxOpenFiles < 64) {
            throw new IllegalArgumentException("resource limits too low");
        }
    }

    /** Heap size to give a JVM tool: 75 % of the address-space limit, leaving room for metaspace/threads. */
    public long jvmHeapBytes() {
        return memoryBytes / 4 * 3;
    }
}
