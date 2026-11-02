package com.africodeshield.core.scan;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CommandSpecTest {

    private final Path work = Path.of("/tmp/acs/job-1/trivy");

    @Test
    void acceptsAbsoluteExecutableAndSafeEnvironment() {
        assertDoesNotThrow(() -> new CommandSpec(List.of("/opt/tools/trivy", "fs", "--offline-scan", "/src"),
                Map.of("HOME", "/tmp/acs/job-1/trivy", "TRIVY_CACHE_DIR", "/var/lib/acs/trivy"),
                work, work.resolve("report.json")));
    }

    @Test
    void rejectsRelativeExecutable() {
        assertThrows(IllegalArgumentException.class,
                () -> new CommandSpec(List.of("trivy"), Map.of(), work, work.resolve("r.json")));
    }

    @Test
    void rejectsCredentialLikeEnvironmentVariables() {
        for (String name : List.of("GITLAB_TOKEN", "GIT_ASKPASS", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "NPM_AUTH")) {
            assertThrows(IllegalArgumentException.class,
                    () -> new CommandSpec(List.of("/bin/x"), Map.of(name, "v"), work, work.resolve("r.json")),
                    name);
        }
    }

    @Test
    void reportMustStayInsideWorkingDirectory() {
        assertThrows(IllegalArgumentException.class,
                () -> new CommandSpec(List.of("/bin/x"), Map.of(), work, Path.of("/tmp/acs/job-1/trivy/../../escape.json")));
    }

    @Test
    void workDirCannotBeInsideSources() {
        Path src = Path.of("/tmp/acs/job-1/src");
        assertThrows(IllegalArgumentException.class, () -> new ScanContext(UUID.randomUUID(), src,
                src.resolve("out"), "abc", ResourceLimits.DEFAULT, Map.of()));
    }

    @Test
    void resourceLimitsValidationAndHeap() {
        assertThrows(IllegalArgumentException.class,
                () -> new ResourceLimits(Duration.ZERO, 10, 1L << 30, 1L << 20, 128));
        assertThrows(IllegalArgumentException.class,
                () -> new ResourceLimits(Duration.ofHours(7), 10, 1L << 30, 1L << 20, 128));
        assertEquals(1_610_612_736L, ResourceLimits.DEFAULT.jvmHeapBytes());
    }
}
