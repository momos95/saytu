package com.saytu.scan.sandbox;

import com.saytu.core.finding.SecretRedactor;
import com.saytu.core.scan.CommandSpec;
import com.saytu.core.scan.ResourceLimits;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Runs external tools (scanners, git) as bounded child processes.
 * <p>
 * Guarantees for every process:
 * <ul>
 *   <li>argv only, no shell; standard input is {@code /dev/null};</li>
 *   <li>the environment is exactly the one given (the worker's own environment, which holds the
 *       database password and the master key, is never inherited);</li>
 *   <li>kernel limits through {@code prlimit}: CPU time, size of written files, open descriptors, no
 *       core dump;</li>
 *   <li>memory: the resident memory (RSS) of the whole process tree is sampled from {@code /proc}
 *       and the tree is killed above the limit. The address-space limit (RLIMIT_AS) is not used:
 *       Go and OCaml runtimes reserve several GB of virtual memory up front (Gitleaks and Opengrep
 *       fail to start below 8 GB), so it cannot express a real memory budget;</li>
 *   <li>wall-clock timeout: the whole process tree is killed, then the result says {@code timedOut};</li>
 *   <li>stdout / stderr go to files in the working directory, only their tails are kept, with secrets masked.</li>
 * </ul>
 * Without {@code prlimit} (developer machine) the limits are not applied unless {@code enforceLimits}
 * is set, in which case construction fails: the worker image always enforces them.
 */
public final class ProcessSandbox {

    private static final Logger LOG = Logger.getLogger(ProcessSandbox.class.getName());
    private static final List<Path> PRLIMIT_LOCATIONS = List.of(Path.of("/usr/bin/prlimit"), Path.of("/bin/prlimit"));
    static final String STDOUT_FILE = ".saytu-stdout.log";
    static final String STDERR_FILE = ".saytu-stderr.log";
    private static final long POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(250);

    private final Path prlimit;
    private final int tailBytes;

    /**
     * @param prlimit   path of util-linux {@code prlimit}, or {@code null} to run without kernel limits
     * @param tailBytes how much of stdout / stderr to keep
     */
    public ProcessSandbox(Path prlimit, int tailBytes) {
        if (prlimit != null && !Files.isExecutable(prlimit)) {
            throw new IllegalArgumentException("prlimit is not executable: " + prlimit);
        }
        if (tailBytes < 256) {
            throw new IllegalArgumentException("tailBytes too small");
        }
        this.prlimit = prlimit;
        this.tailBytes = tailBytes;
    }

    /** Uses {@code prlimit} when installed; fails if it is missing and {@code enforceLimits} is set. */
    public static ProcessSandbox detect(boolean enforceLimits) {
        Path found = PRLIMIT_LOCATIONS.stream().filter(Files::isExecutable).findFirst().orElse(null);
        if (found == null) {
            if (enforceLimits) {
                throw new IllegalStateException("prlimit (util-linux) is required to run scanners with resource limits");
            }
            LOG.warning("prlimit not found: scanner processes run WITHOUT CPU / memory / file-size limits");
        }
        return new ProcessSandbox(found, 8 * 1024);
    }

    public boolean enforcesLimits() {
        return prlimit != null;
    }

    /** Runs a scanner command. The environment rules of {@link CommandSpec} apply (no credential). */
    public SandboxResult run(CommandSpec spec, ResourceLimits limits) throws IOException, InterruptedException {
        return execute(spec.argv(), spec.environment(), spec.workingDir(), limits, List.of());
    }

    /**
     * Runs a trusted helper (git) whose environment may carry a credential. The credential values in
     * {@code secretsToMask} are removed from the captured output.
     */
    public SandboxResult runTrusted(List<String> argv, Map<String, String> environment, Path workingDir,
                                    ResourceLimits limits, Collection<String> secretsToMask)
            throws IOException, InterruptedException {
        if (argv.isEmpty() || !argv.getFirst().startsWith("/")) {
            throw new IllegalArgumentException("argv[0] must be an absolute executable path");
        }
        return execute(List.copyOf(argv), Map.copyOf(environment), workingDir, limits, secretsToMask);
    }

    private SandboxResult execute(List<String> argv, Map<String, String> environment, Path workingDir,
                                  ResourceLimits limits, Collection<String> secrets)
            throws IOException, InterruptedException {
        Objects.requireNonNull(limits, "limits");
        Files.createDirectories(workingDir);
        Path stdout = workingDir.resolve(STDOUT_FILE);
        Path stderr = workingDir.resolve(STDERR_FILE);

        ProcessBuilder builder = new ProcessBuilder(withLimits(argv, limits))
                .directory(workingDir.toFile())
                .redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")))
                .redirectOutput(stdout.toFile())
                .redirectError(stderr.toFile());
        builder.environment().clear();
        builder.environment().putAll(environment);

        long start = System.nanoTime();
        long deadline = start + limits.timeout().toNanos();
        Process process = builder.start();
        boolean finished = false;
        boolean memoryExceeded = false;
        long peakRss = 0;
        try {
            while (!finished) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    break;
                }
                finished = process.waitFor(Math.min(remaining, POLL_NANOS), TimeUnit.NANOSECONDS);
                if (!finished) {
                    long rss = treeRssBytes(process);
                    peakRss = Math.max(peakRss, rss);
                    if (rss > limits.memoryBytes()) {
                        memoryExceeded = true;
                        break;
                    }
                }
            }
        } catch (InterruptedException e) {
            killTree(process);
            throw e;
        }
        if (!finished) {
            killTree(process);
        }
        Duration duration = Duration.ofNanos(System.nanoTime() - start);
        int exit = finished ? process.exitValue() : -1;
        return new SandboxResult(exit, !finished && !memoryExceeded, memoryExceeded, peakRss, duration,
                tail(stdout, secrets), tail(stderr, secrets));
    }

    /** Sum of VmRSS of the process and its descendants; 0 when /proc is not available. */
    static long treeRssBytes(Process process) {
        long total = rssBytes(process.pid());
        for (ProcessHandle child : process.descendants().toList()) {
            total += rssBytes(child.pid());
        }
        return total;
    }

    private static long rssBytes(long pid) {
        Path status = Path.of("/proc", Long.toString(pid), "status");
        try {
            for (String line : Files.readAllLines(status, StandardCharsets.ISO_8859_1)) {
                if (line.startsWith("VmRSS:")) {
                    String[] parts = line.substring(6).trim().split("\\s+");
                    return Long.parseLong(parts[0]) * 1024;
                }
            }
        } catch (IOException | RuntimeException e) {
            // process already gone, or not Linux
        }
        return 0;
    }

    private List<String> withLimits(List<String> argv, ResourceLimits limits) {
        if (prlimit == null) {
            return argv;
        }
        List<String> command = new ArrayList<>(argv.size() + 8);
        command.add(prlimit.toString());
        command.add("--cpu=" + limits.cpuSeconds() + ":" + limits.cpuSeconds());
        command.add("--fsize=" + limits.maxOutputBytes() + ":" + limits.maxOutputBytes());
        command.add("--nofile=" + limits.maxOpenFiles() + ":" + limits.maxOpenFiles());
        command.add("--core=0:0");
        command.add("--");
        command.addAll(argv);
        return command;
    }

    /** Kills descendants first so that grandchildren cannot outlive the timeout. */
    private static void killTree(Process process) {
        process.descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        try {
            process.waitFor(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        process.descendants().forEach(ProcessHandle::destroyForcibly);
    }

    private String tail(Path file, Collection<String> secrets) throws IOException {
        if (!Files.exists(file)) {
            return "";
        }
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            long length = raf.length();
            long from = Math.max(0, length - tailBytes);
            byte[] bytes = new byte[(int) (length - from)];
            raf.seek(from);
            raf.readFully(bytes);
            String text = new String(bytes, StandardCharsets.UTF_8);
            if (from > 0) {
                int newline = text.indexOf('\n');
                text = "…" + (newline >= 0 ? text.substring(newline + 1) : text);
            }
            // ANSI colour codes make the messages unreadable in the UI
            text = text.replaceAll("\u001B\\[[0-9;]*[A-Za-z]", "");
            return SecretRedactor.redact(text, secrets);
        }
    }
}
