package com.saytu.scan;

import com.saytu.core.scan.ResourceLimits;
import com.saytu.scan.git.GitCheckout;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Test helpers: temporary directories, git repositories built with the real git CLI, and the
 * location of the real scanner binaries.
 * <p>
 * Tests that need Opengrep / Trivy / Gitleaks run only when {@code SAYTU_TOOLS_DIR} points to a
 * directory containing {@code opengrep}, {@code trivy} and {@code gitleaks} (the worker image sets
 * it); otherwise they are skipped, never faked.
 */
public final class TestSupport {

    public static final Path GIT = Path.of("/usr/bin/git");
    public static final ResourceLimits SMALL = new ResourceLimits(Duration.ofSeconds(60), 60,
            1024L * 1024 * 1024, 64L * 1024 * 1024, 1024);

    private TestSupport() {
    }

    public static Path tempDir(String prefix) throws IOException {
        return Files.createTempDirectory(prefix).toRealPath();
    }

    public static void delete(Path dir) {
        try {
            GitCheckout.deleteRecursively(dir);
        } catch (IOException e) {
            // best effort
        }
    }

    /** Runs a command and returns its stdout; fails on non-zero exit. */
    public static String sh(Path dir, String... argv) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(argv).directory(dir.toFile()).redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        env.put("GIT_CONFIG_NOSYSTEM", "1");
        env.put("GIT_CONFIG_GLOBAL", "/dev/null");
        env.put("GIT_AUTHOR_NAME", "t");
        env.put("GIT_AUTHOR_EMAIL", "t@example.org");
        env.put("GIT_COMMITTER_NAME", "t");
        env.put("GIT_COMMITTER_EMAIL", "t@example.org");
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IOException(String.join(" ", argv) + " failed: " + out);
        }
        return out;
    }

    public static String git(Path repo, String... args) throws IOException, InterruptedException {
        List<String> argv = new ArrayList<>(List.of(GIT.toString(), "-C", repo.toString()));
        argv.addAll(List.of(args));
        return sh(repo, argv.toArray(String[]::new)).strip();
    }

    /** New repository with branch {@code main} and the given files committed. */
    public static Path repo(Path parent, String name, Map<String, String> files) throws IOException, InterruptedException {
        Path repo = parent.resolve(name);
        Files.createDirectories(repo);
        git(repo, "init", "-q", "-b", "main");
        write(repo, files);
        git(repo, "add", "-A");
        git(repo, "commit", "-q", "-m", "initial");
        return repo;
    }

    public static void write(Path root, Map<String, String> files) throws IOException {
        for (var e : files.entrySet()) {
            Path f = root.resolve(e.getKey());
            Files.createDirectories(f.getParent());
            Files.writeString(f, e.getValue(), StandardCharsets.UTF_8);
        }
    }

    // ---------------------------------------------------------------- real tools

    public static Path toolsDir() {
        String dir = System.getenv("SAYTU_TOOLS_DIR");
        return dir == null || dir.isBlank() ? null : Path.of(dir);
    }

    public static Path tool(String name) {
        Path dir = toolsDir();
        if (dir == null) {
            return null;
        }
        Path p = dir.resolve(name);
        return Files.isExecutable(p) ? p : null;
    }

    /** A file or directory of the tools directory (e.g. "checkstyle", "phpcs/bin/phpcs"), or {@code null}. */
    public static Path toolPath(String relative) {
        Path dir = toolsDir();
        if (dir == null) {
            return null;
        }
        Path p = dir.resolve(relative);
        return Files.exists(p) ? p : null;
    }

    /** First existing executable among the candidates, or {@code null}. */
    public static Path executable(String... candidates) {
        for (String c : candidates) {
            if (c == null) {
                continue;
            }
            Path p = Path.of(c);
            if (Files.isExecutable(p)) {
                return p;
            }
        }
        return null;
    }

    /** The java launcher of the JVM running the tests. */
    public static Path java() {
        return ProcessHandle.current().info().command().map(Path::of).filter(Files::isExecutable).orElse(null);
    }

    /** Pre-extracted Opengrep runtime (worker image build), {@code null} to extract per run. */
    public static Path opengrepRuntime() {
        String dir = System.getenv("SAYTU_OPENGREP_RUNTIME");
        return dir == null || dir.isBlank() || !Files.isDirectory(Path.of(dir)) ? null : Path.of(dir);
    }

    /** Repository root (contains scanners/), found from the working directory upwards. */
    public static Path repositoryRoot() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null) {
            if (Files.isDirectory(p.resolve("scanners").resolve("opengrep"))) {
                return p;
            }
            p = p.getParent();
        }
        String env = System.getenv("SAYTU_REPO_ROOT");
        return env == null ? null : Path.of(env);
    }

    /** Secret-like strings assembled at run time so that no token format appears in the sources. */
    public static String fakeGithubToken() {
        return "gh" + "p_" + "R7c9Qx2LmVb8TzW4kHn6JpYs3DfGa1EuXo5N";
    }

    public static String fakeAwsKeyId() {
        return "AK" + "IA" + "QZ7KXP2M4TBWJ6RN";
    }
}
