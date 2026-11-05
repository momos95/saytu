package com.saytu.scan.sandbox;

import com.saytu.core.scan.CommandSpec;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.scan.TestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ProcessSandboxTest {

    private Path dir;
    private ProcessSandbox sandbox;

    @BeforeEach
    void setUp() throws Exception {
        dir = TestSupport.tempDir("sandbox");
        sandbox = ProcessSandbox.detect(false);
    }

    @AfterEach
    void tearDown() {
        TestSupport.delete(dir);
    }

    private CommandSpec sh(String script, Map<String, String> env) {
        return new CommandSpec(List.of("/bin/sh", "-c", script), env, dir, dir.resolve("report"));
    }

    private static ResourceLimits limits(Duration timeout, long memoryBytes, long maxOutput) {
        return new ResourceLimits(timeout, 60, memoryBytes, maxOutput, 256);
    }

    @Test
    void environmentIsExactlyTheGivenOne() throws Exception {
        SandboxResult r = sandbox.run(sh("env", Map.of("ONLY_VAR", "1")), TestSupport.SMALL);
        assertEquals(0, r.exitCode());
        List<String> lines = r.stdoutTail().strip().lines()
                .filter(l -> !l.startsWith("PWD=") && !l.startsWith("SHLVL=") && !l.startsWith("_=")).toList();
        assertEquals(List.of("ONLY_VAR=1"), lines, "the worker's own environment must not leak");
    }

    @Test
    void timeoutKillsTheWholeProcessTree() throws Exception {
        long before = System.nanoTime();
        SandboxResult r = sandbox.run(sh("sleep 30 & sleep 30; wait", Map.of()),
                limits(Duration.ofSeconds(1), 512L * 1024 * 1024, 1024 * 1024));
        assertTrue(r.timedOut());
        assertFalse(r.completed());
        assertTrue(Duration.ofNanos(System.nanoTime() - before).toSeconds() < 20, "should not wait for the children");
        Thread.sleep(300);
        boolean orphan = ProcessHandle.allProcesses()
                .anyMatch(p -> p.info().commandLine().map(c -> c.contains("sleep 30")).orElse(false)
                        && p.parent().map(pp -> pp.pid() == 1).orElse(false));
        assertFalse(orphan, "background child must be killed too");
    }

    @Test
    void outputTailMasksGivenSecrets() throws Exception {
        String secret = "s3cr3t-value-" + System.nanoTime();
        SandboxResult r = sandbox.runTrusted(List.of("/bin/sh", "-c", "echo \"fatal: token $T rejected\" >&2; exit 3"),
                Map.of("T", secret), dir, TestSupport.SMALL, List.of(secret));
        assertEquals(3, r.exitCode());
        assertFalse(r.stderrTail().contains(secret));
        assertTrue(r.diagnostic(200).contains("rejected"));
    }

    @Test
    void kernelLimitsAreAppliedWhenPrlimitIsInstalled() throws Exception {
        assumeTrue(sandbox.enforcesLimits(), "prlimit not installed");
        SandboxResult r = sandbox.run(sh("ulimit -n; ulimit -t", Map.of()),
                new ResourceLimits(Duration.ofSeconds(10), 42, 512L * 1024 * 1024, 2L * 1024 * 1024, 77));
        assertEquals(List.of("77", "42"), r.stdoutTail().strip().lines().toList());
    }

    @Test
    void writtenFileSizeIsCapped() throws Exception {
        assumeTrue(sandbox.enforcesLimits(), "prlimit not installed");
        SandboxResult r = sandbox.run(sh("head -c 8000000 /dev/zero > big.bin", Map.of("PATH", "/usr/bin:/bin")),
                limits(Duration.ofSeconds(10), 512L * 1024 * 1024, 1024 * 1024));
        assertTrue(r.exitCode() != 0, "SIGXFSZ expected");
        assertTrue(Files.size(dir.resolve("big.bin")) <= 1024 * 1024);
    }

    @Test
    void residentMemoryAboveTheLimitKillsTheProcess() throws Exception {
        assumeTrue(Files.isDirectory(Path.of("/proc/self")), "needs /proc");
        Path java = ProcessHandle.current().info().command().map(Path::of).orElse(null);
        assumeTrue(java != null && Files.isExecutable(java), "java launcher not found");
        Path program = dir.resolve("Hog.java");
        Files.writeString(program, "class Hog { public static void main(String[] a) throws Exception { Thread.sleep(20000); } }");
        CommandSpec spec = new CommandSpec(List.of(java.toString(), "-Xms400m", "-Xmx400m", "-XX:+AlwaysPreTouch",
                "-XX:+UseSerialGC", program.toString()), Map.of(), dir, dir.resolve("report"));
        SandboxResult r = sandbox.run(spec, limits(Duration.ofSeconds(60), 200L * 1024 * 1024, 64L * 1024 * 1024));
        assertTrue(r.memoryExceeded(), "process using ~400 MB with a 200 MB limit must be killed");
        assertFalse(r.timedOut());
        assertTrue(r.peakRssBytes() > 200L * 1024 * 1024);
    }
}
