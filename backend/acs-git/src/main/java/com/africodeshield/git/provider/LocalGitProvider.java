package com.africodeshield.git.provider;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProvider;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.core.git.GitProviderException.Kind;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Repositories stored on a directory mounted read-only into the containers (e.g. mirrors, exports).
 * <p>
 * Connections may only point inside the configured root ({@code ACS_LOCAL_REPOS_ROOT}); paths are
 * resolved with symbolic links followed, so a link cannot escape the root. Without a root, local
 * connections are disabled.
 */
public final class LocalGitProvider implements GitProvider {

    static final int MAX_DEPTH = 3;

    private final Path root;

    /** @param root allowed root directory, {@code null} to disable local connections */
    public LocalGitProvider(Path root) {
        this.root = root;
    }

    @Override
    public GitProviderType type() {
        return GitProviderType.LOCAL;
    }

    @Override
    public ConnectionTestResult testConnection(GitConnectionSpec connection) {
        try {
            Path dir = resolve(connection);
            int repositories = countRepositories(dir, 0);
            List<String> warnings = new ArrayList<>();
            if (repositories == 0) {
                warnings.add("No Git repository found in " + display(dir) + " (searched " + MAX_DEPTH + " levels deep).");
            }
            return ConnectionTestResult.ok(null, repositories + " repositor" + (repositories == 1 ? "y" : "ies") + " found",
                    List.of(), warnings, null);
        } catch (GitProviderException e) {
            return ConnectionTestResult.failure(e);
        }
    }

    /** Resolves the connection directory and checks it stays inside the root. */
    Path resolve(GitConnectionSpec connection) {
        if (root == null) {
            throw new GitProviderException(Kind.BLOCKED_BY_POLICY,
                    "Local repositories are disabled: set ACS_LOCAL_REPOS_ROOT and mount the directory read-only.");
        }
        Path requested;
        try {
            requested = Path.of(connection.baseUrl());
        } catch (IllegalArgumentException | java.nio.file.FileSystemNotFoundException e) {
            throw new GitProviderException(Kind.BLOCKED_BY_POLICY, "Invalid local path URI");
        }
        Path realRoot;
        Path real;
        try {
            realRoot = root.toRealPath();
        } catch (IOException e) {
            throw new GitProviderException(Kind.NOT_FOUND, "Configured local root " + root + " does not exist.");
        }
        try {
            real = requested.toRealPath();
        } catch (IOException e) {
            throw new GitProviderException(Kind.NOT_FOUND, "Directory " + requested + " does not exist or is not readable.");
        }
        if (!real.startsWith(realRoot)) {
            throw new GitProviderException(Kind.BLOCKED_BY_POLICY, "Directory " + requested + " is outside the allowed root "
                    + root + " (symbolic links are resolved).");
        }
        if (!Files.isDirectory(real) || !Files.isReadable(real)) {
            throw new GitProviderException(Kind.INSUFFICIENT_PERMISSIONS, "Directory " + requested + " is not a readable directory.");
        }
        return real;
    }

    static boolean isRepository(Path dir) {
        if (Files.isDirectory(dir.resolve(".git"), LinkOption.NOFOLLOW_LINKS)
                || Files.isRegularFile(dir.resolve(".git"), LinkOption.NOFOLLOW_LINKS)) {
            return true;
        }
        // bare repository
        return Files.isRegularFile(dir.resolve("HEAD")) && Files.isDirectory(dir.resolve("objects"))
                && Files.isDirectory(dir.resolve("refs"));
    }

    private static int countRepositories(Path dir, int depth) {
        if (isRepository(dir)) {
            return 1;
        }
        if (depth >= MAX_DEPTH) {
            return 0;
        }
        int count = 0;
        try (DirectoryStream<Path> children = Files.newDirectoryStream(dir,
                p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) && !p.getFileName().toString().startsWith("."))) {
            for (Path child : children) {
                count += countRepositories(child, depth + 1);
            }
        } catch (IOException e) {
            return count;
        }
        return count;
    }

    private String display(Path dir) {
        return dir.toString();
    }

    @Override
    public Page<Namespace> listNamespaces(GitConnectionSpec connection, PageRequest page) {
        throw new UnsupportedOperationException(AbstractHttpGitProvider.DISCOVERY_PHASE);
    }

    @Override
    public Page<RemoteRepository> listRepositories(GitConnectionSpec connection, String namespaceExternalId,
                                                   PageRequest page) {
        throw new UnsupportedOperationException(AbstractHttpGitProvider.DISCOVERY_PHASE);
    }

    @Override
    public Page<RemoteBranch> listBranches(GitConnectionSpec connection, String repositoryExternalId, PageRequest page) {
        throw new UnsupportedOperationException(AbstractHttpGitProvider.DISCOVERY_PHASE);
    }

    @Override
    public Optional<String> resolveHeadCommit(GitConnectionSpec connection, String repositoryExternalId, String branch) {
        throw new UnsupportedOperationException(AbstractHttpGitProvider.DISCOVERY_PHASE);
    }
}
