package com.saytu.scan.git;

import com.saytu.core.scan.ResourceLimits;
import com.saytu.scan.sandbox.ProcessSandbox;
import com.saytu.scan.sandbox.SandboxResult;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Shallow, hardened clone of one branch.
 * <p>
 * Defences against a hostile repository or server:
 * <ul>
 *   <li>no hooks ({@code core.hooksPath=/dev/null}), no submodules, no LFS smudge, no fsmonitor, no
 *       global or system git configuration;</li>
 *   <li>symbolic links are checked out as plain files ({@code core.symlinks=false}), and any link left
 *       is removed, so no file can point outside the working tree;</li>
 *   <li>only the {@code https} transport is allowed (plus {@code http} when the connection was
 *       explicitly allowed to, and {@code file} for LOCAL connections under the configured root);
 *       redirects are not followed;</li>
 *   <li>credentials travel as an {@code Authorization} header defined through {@code GIT_CONFIG_*}
 *       environment variables of the git process only, scoped to the clone origin;</li>
 *   <li>{@code .git} is deleted after the commit id is read: scanners never see the remote URL or
 *       any credential, and cannot run git commands against the remote;</li>
 *   <li>bounded time, CPU and written bytes (sandbox), plus a size and file-count quota.</li>
 * </ul>
 */
public final class GitCheckout {

    private static final Pattern SHA = Pattern.compile("^[0-9a-f]{40}([0-9a-f]{24})?$");

    /**
     * @param git             absolute path of the git executable
     * @param limits          limits of the git processes (time, CPU, memory, written bytes)
     * @param maxBytes        quota on the size of the checked-out tree
     * @param maxFiles        quota on the number of files
     * @param caBundle        extra CA bundle (PEM) for internal Git servers, or {@code null}
     * @param allowPlainHttp  allow {@code http://} clone URLs (lab only)
     * @param localReposRoot  root directory of LOCAL repositories, or {@code null} if none are configured
     * @param proxyEnvironment HTTPS_PROXY / NO_PROXY... passed to git, may be empty
     */
    public record Settings(Path git, ResourceLimits limits, long maxBytes, long maxFiles, Path caBundle,
                           boolean allowPlainHttp, Path localReposRoot, Map<String, String> proxyEnvironment) {
        public Settings {
            Objects.requireNonNull(git, "git");
            Objects.requireNonNull(limits, "limits");
            if (!git.isAbsolute()) {
                throw new IllegalArgumentException("git must be an absolute path");
            }
            if (maxBytes < 1024 * 1024 || maxFiles < 1) {
                throw new IllegalArgumentException("checkout quota too low");
            }
            proxyEnvironment = proxyEnvironment == null ? Map.of() : Map.copyOf(proxyEnvironment);
        }
    }

    private final ProcessSandbox sandbox;
    private final Settings settings;

    public GitCheckout(ProcessSandbox sandbox, Settings settings) {
        this.sandbox = Objects.requireNonNull(sandbox, "sandbox");
        this.settings = Objects.requireNonNull(settings, "settings");
    }

    /**
     * Clones {@code request} into {@code jobDir/src}.
     *
     * @param jobDir private (0700), empty directory owned by the job; deleted by the caller
     */
    public CheckoutResult checkout(CheckoutRequest request, Path jobDir) throws CheckoutException, InterruptedException {
        URI source = validate(request);
        Path home = jobDir.resolve("git-home");
        Path dest = jobDir.resolve("src");
        try {
            Files.createDirectories(home);
        } catch (IOException e) {
            throw new CheckoutException(CheckoutException.Kind.FAILED, "cannot prepare the checkout directory");
        }
        boolean local = "file".equals(source.getScheme());

        Map<String, String> env = baseEnvironment(home);
        List<String> configs = new ArrayList<>();
        List<String> secrets = List.of();
        if (request.credentials() != null) {
            if (local) {
                throw new CheckoutException(CheckoutException.Kind.BLOCKED_BY_POLICY, "local repositories take no credentials");
            }
            configs.add("http." + origin(source) + "/.extraHeader");
            configs.add(request.credentials().authorizationHeader());
            secrets = request.credentials().sensitiveStrings();
        }
        for (int i = 0; i < configs.size() / 2; i++) {
            env.put("GIT_CONFIG_KEY_" + i, configs.get(2 * i));
            env.put("GIT_CONFIG_VALUE_" + i, configs.get(2 * i + 1));
        }
        env.put("GIT_CONFIG_COUNT", Integer.toString(configs.size() / 2));

        List<String> clone = new ArrayList<>(gitWithHardening(local, request.verifyTls()));
        if (local) {
            // the mounted repository belongs to another user: trust exactly this path, nothing else
            clone.add(1, "-c");
            clone.add(2, "safe.directory=" + Path.of(source).toString());
            clone.add(3, "-c");
            clone.add(4, "safe.directory=" + Path.of(source).resolve(".git"));
        }
        clone.addAll(List.of("clone", "--quiet", "--depth", "1", "--single-branch", "--branch", request.branch(),
                "--no-tags", "--no-recurse-submodules"));
        if (local) {
            clone.add("--no-hardlinks");
        }
        clone.addAll(List.of("--", source.toString(), dest.toString()));

        SandboxResult result = run(clone, env, jobDir, secrets);
        if (!result.completed()) {
            throw new CheckoutException(CheckoutException.Kind.TIMEOUT,
                    result.timedOut() ? "clone timed out after " + settings.limits().timeout().toSeconds() + " s"
                            : "clone exceeded the memory limit");
        }
        if (result.exitCode() != 0) {
            throw classify(result.diagnostic(600), request.branch());
        }

        String sha = readHead(dest, env, jobDir);
        sanitize(dest);
        long[] size = measure(dest);
        return new CheckoutResult(dest, sha, size[0], size[1]);
    }

    // ------------------------------------------------------------------ validation

    private URI validate(CheckoutRequest request) throws CheckoutException {
        URI uri = request.cloneUrl();
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (uri.getRawUserInfo() != null) {
            throw new CheckoutException(CheckoutException.Kind.BLOCKED_BY_POLICY, "credentials must not be embedded in the clone URL");
        }
        switch (scheme) {
            case "https" -> {
                return requireHost(uri);
            }
            case "http" -> {
                if (!settings.allowPlainHttp()) {
                    throw new CheckoutException(CheckoutException.Kind.BLOCKED_BY_POLICY, "plain HTTP clone URLs are not allowed");
                }
                return requireHost(uri);
            }
            case "file" -> {
                return validateLocal(uri);
            }
            default -> throw new CheckoutException(CheckoutException.Kind.BLOCKED_BY_POLICY,
                    "unsupported clone URL scheme: " + (scheme.isEmpty() ? "none" : scheme));
        }
    }

    private static URI requireHost(URI uri) throws CheckoutException {
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new CheckoutException(CheckoutException.Kind.BLOCKED_BY_POLICY, "clone URL without host");
        }
        return uri;
    }

    private URI validateLocal(URI uri) throws CheckoutException {
        if (settings.localReposRoot() == null) {
            throw new CheckoutException(CheckoutException.Kind.BLOCKED_BY_POLICY, "no local repository root is configured");
        }
        try {
            Path root = settings.localReposRoot().toRealPath();
            Path repo = Path.of(uri).toRealPath();
            if (!repo.startsWith(root) || repo.equals(root)) {
                throw new CheckoutException(CheckoutException.Kind.BLOCKED_BY_POLICY, "repository outside the local repository root");
            }
            return repo.toUri();
        } catch (IOException | RuntimeException e) {
            throw new CheckoutException(CheckoutException.Kind.NOT_FOUND, "local repository not found");
        }
    }

    private static String origin(URI uri) {
        String port = uri.getPort() < 0 ? "" : ":" + uri.getPort();
        return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT) + port;
    }

    // ------------------------------------------------------------------ git invocation

    private Map<String, String> baseEnvironment(Path home) {
        Map<String, String> env = new LinkedHashMap<>();
        env.put("PATH", "/usr/local/bin:/usr/bin:/bin");
        env.put("HOME", home.toString());
        env.put("LANG", "C.UTF-8");
        env.put("GIT_CONFIG_NOSYSTEM", "1");
        env.put("GIT_CONFIG_GLOBAL", "/dev/null");
        env.put("GIT_TERMINAL_PROMPT", "0");
        env.put("GIT_ASKPASS", "/bin/false");
        env.put("SSH_ASKPASS", "/bin/false");
        env.put("GIT_LFS_SKIP_SMUDGE", "1");
        env.put("GIT_PROTOCOL_FROM_USER", "0");
        if (settings.caBundle() != null) {
            env.put("GIT_SSL_CAINFO", settings.caBundle().toString());
        }
        env.putAll(settings.proxyEnvironment());
        return env;
    }

    private List<String> gitWithHardening(boolean local, boolean verifyTls) {
        List<String> argv = new ArrayList<>();
        argv.add(settings.git().toString());
        String[] configs = {
                "core.hooksPath=/dev/null",
                "core.symlinks=false",
                "core.fsmonitor=false",
                "core.protectNTFS=true",
                "core.protectHFS=true",
                "credential.helper=",
                "submodule.recurse=false",
                "fetch.recurseSubmodules=false",
                "http.followRedirects=false",
                "filter.lfs.smudge=",
                "filter.lfs.process=",
                "filter.lfs.required=false",
                "protocol.allow=never",
                "protocol.https.allow=always",
                "protocol.http.allow=" + (settings.allowPlainHttp() ? "always" : "never"),
                "protocol.file.allow=" + (local ? "always" : "never"),
                "http.sslVerify=" + verifyTls,
                "advice.detachedHead=false",
        };
        for (String config : configs) {
            argv.add("-c");
            argv.add(config);
        }
        return argv;
    }

    private SandboxResult run(List<String> argv, Map<String, String> env, Path workDir, List<String> secrets)
            throws CheckoutException, InterruptedException {
        try {
            return sandbox.runTrusted(argv, env, workDir, settings.limits(), secrets);
        } catch (IOException e) {
            throw new CheckoutException(CheckoutException.Kind.FAILED, "cannot start git: " + e.getMessage());
        }
    }

    private String readHead(Path dest, Map<String, String> cloneEnv, Path jobDir) throws CheckoutException, InterruptedException {
        Map<String, String> env = new LinkedHashMap<>(cloneEnv);
        env.keySet().removeIf(k -> k.startsWith("GIT_CONFIG_KEY_") || k.startsWith("GIT_CONFIG_VALUE_"));
        env.put("GIT_CONFIG_COUNT", "0");
        List<String> argv = List.of(settings.git().toString(), "-c", "safe.directory=" + dest,
                "-C", dest.toString(), "rev-parse", "--verify", "HEAD^{commit}");
        SandboxResult result = run(argv, env, jobDir, List.of());
        String sha = result.stdoutTail().strip();
        if (result.exitCode() != 0 || !SHA.matcher(sha).matches()) {
            throw new CheckoutException(CheckoutException.Kind.FAILED, "cannot read the checked-out commit");
        }
        return sha;
    }

    // ------------------------------------------------------------------ post-processing

    /** Removes .git and any symbolic link (none should exist with core.symlinks=false). */
    private static void sanitize(Path dest) throws CheckoutException {
        try {
            deleteRecursively(dest.resolve(".git"));
            List<Path> links = new ArrayList<>();
            Files.walkFileTree(dest, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (attrs.isSymbolicLink() || attrs.isOther()) {
                        links.add(file);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
            for (Path link : links) {
                Files.deleteIfExists(link);
            }
        } catch (IOException e) {
            throw new CheckoutException(CheckoutException.Kind.FAILED, "cannot clean the checkout");
        }
    }

    private long[] measure(Path dest) throws CheckoutException {
        long[] totals = new long[2];
        try {
            Files.walkFileTree(dest, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (attrs.isRegularFile()) {
                        totals[0] += attrs.size();
                        totals[1]++;
                        if (totals[0] > settings.maxBytes() || totals[1] > settings.maxFiles()) {
                            throw new QuotaExceeded();
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (QuotaExceeded e) {
            throw new CheckoutException(CheckoutException.Kind.TOO_LARGE, "checkout exceeds the quota ("
                    + settings.maxBytes() / (1024 * 1024) + " MB, " + settings.maxFiles() + " files)");
        } catch (IOException e) {
            throw new CheckoutException(CheckoutException.Kind.FAILED, "cannot measure the checkout");
        }
        return totals;
    }

    private static final class QuotaExceeded extends IOException {
        private static final long serialVersionUID = 1L;
    }

    /** Deletes a tree, also when the tool made files read-only. Never follows symbolic links. */
    public static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                dir.toFile().setWritable(true, true);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                Files.deleteIfExists(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    // ------------------------------------------------------------------ error mapping

    static CheckoutException classify(String stderr, String branch) {
        String s = stderr.toLowerCase(Locale.ROOT);
        CheckoutException.Kind kind;
        String message;
        if (s.contains("remote branch") && s.contains("not found")) {
            kind = CheckoutException.Kind.BRANCH_NOT_FOUND;
            message = "branch '" + branch + "' not found";
        } else if (s.contains("authentication failed") || s.contains("could not read username")
                || s.contains("could not read password") || s.contains("returned error: 401")
                || s.contains("invalid username or password") || s.contains("terminal prompts disabled")) {
            kind = CheckoutException.Kind.AUTHENTICATION_FAILED;
            message = "authentication refused by the Git server (token missing, expired or without read access)";
        } else if (s.contains("returned error: 403")) {
            kind = CheckoutException.Kind.AUTHENTICATION_FAILED;
            message = "access denied by the Git server (HTTP 403)";
        } else if (s.contains("not found") || s.contains("returned error: 404") || s.contains("does not appear to be a git repository")) {
            kind = CheckoutException.Kind.NOT_FOUND;
            message = "repository not found or not visible to the credentials";
        } else if (s.contains("ssl certificate problem") || s.contains("server certificate verification failed")
                || s.contains("unable to get local issuer certificate") || s.contains("certificate verify failed")) {
            kind = CheckoutException.Kind.TLS_ERROR;
            message = "TLS certificate not trusted (add the internal or proxy CA to data/ca)";
        } else if (s.contains("could not resolve host") || s.contains("failed to connect") || s.contains("connection refused")
                || s.contains("connection timed out") || s.contains("network is unreachable")) {
            kind = CheckoutException.Kind.UNREACHABLE;
            message = "Git server unreachable";
        } else if (s.contains("redirect")) {
            kind = CheckoutException.Kind.BLOCKED_BY_POLICY;
            message = "the Git server answered with a redirect, which is not followed";
        } else if (s.contains("transport") && s.contains("not allowed")) {
            kind = CheckoutException.Kind.BLOCKED_BY_POLICY;
            message = "transport not allowed by policy";
        } else {
            kind = CheckoutException.Kind.FAILED;
            message = "git clone failed: " + stderr.strip();
        }
        return new CheckoutException(kind, message);
    }
}
