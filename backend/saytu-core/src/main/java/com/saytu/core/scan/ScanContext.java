package com.saytu.core.scan;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Inputs of one scanner run on one checked-out branch.
 *
 * @param scanJobId    job being executed
 * @param sourceDir    read-only checkout of the branch (no {@code .git} credentials, no hooks)
 * @param workDir      empty, private (0700) temporary directory dedicated to this scanner run
 * @param commitSha    analysed commit
 * @param limits       sandbox limits
 * @param settings     scanner-specific options from {@code scanner_config.settings}
 */
public record ScanContext(UUID scanJobId, Path sourceDir, Path workDir, String commitSha,
                          ResourceLimits limits, Map<String, String> settings) {

    public ScanContext {
        Objects.requireNonNull(scanJobId, "scanJobId");
        Objects.requireNonNull(sourceDir, "sourceDir");
        Objects.requireNonNull(workDir, "workDir");
        Objects.requireNonNull(limits, "limits");
        if (workDir.normalize().startsWith(sourceDir.normalize())) {
            throw new IllegalArgumentException("workDir must not be inside the analysed sources");
        }
        settings = settings == null ? Map.of() : Map.copyOf(settings);
    }
}
