package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.domain.NamespaceKind;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProvider;
import com.saytu.core.git.GitProviderException;
import com.saytu.core.git.GitProviderException.Kind;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Repositories stored on a directory mounted read-only into the containers (e.g. mirrors, exports).
 * <p>
 * Connections may only point inside the configured root ({@code SAYTU_LOCAL_REPOS_ROOT}); paths are
 * resolved with symbolic links followed, so a link cannot escape the root. Without a root, local
 * connections are disabled.
 * <p>
 * Discovery reads Git metadata files directly ({@code HEAD}, {@code refs/heads}, {@code packed-refs}):
 * no git process is started and nothing in the repository is executed.
 */
public final class LocalGitProvider implements GitProvider {

    static final int MAX_DEPTH = 3;
    /** The connection directory is the only namespace. */
    public static final String NAMESPACE_ID = ".";
    private static final Pattern OBJECT_ID = Pattern.compile("[0-9a-f]{40}|[0-9a-f]{64}");
    private static final int MAX_REFS = 20_000;
    private static final long MAX_PACKED_REFS_BYTES = 64L * 1024 * 1024;

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
            int repositories = findRepositories(dir).size();
            List<String> warnings = new ArrayList<>();
            if (repositories == 0) {
                warnings.add("No Git repository found in " + dir + " (searched " + MAX_DEPTH + " levels deep).");
            }
            return ConnectionTestResult.ok(null, repositories + " repositor" + (repositories == 1 ? "y" : "ies") + " found",
                    List.of(), warnings, null);
        } catch (GitProviderException e) {
            return ConnectionTestResult.failure(e);
        }
    }

    // ------------------------------------------------------------------ discovery

    @Override
    public Page<Namespace> listNamespaces(GitConnectionSpec connection, PageRequest page) {
        Path dir = resolve(connection);
        String name = dir.getFileName() == null ? dir.toString() : dir.getFileName().toString();
        return new Page<>(List.of(new Namespace(NAMESPACE_ID, NamespaceKind.LOCAL_DIRECTORY, name, name, null, null)),
                null, 1);
    }

    @Override
    public Optional<Namespace> findNamespace(GitConnectionSpec connection, String path) {
        return Optional.empty();
    }

    @Override
    public Page<RemoteRepository> listRepositories(GitConnectionSpec connection, String namespaceExternalId,
                                                   PageRequest page) {
        Path dir = resolve(connection);
        List<String> all = findRepositories(dir);
        int from = Math.min(offset(page), all.size());
        int to = Math.min(from + page.size(), all.size());
        List<RemoteRepository> items = new ArrayList<>();
        for (String relative : all.subList(from, to)) {
            Path repo = dir.resolve(relative);
            Path gitDir = gitDir(repo, dir);
            Path named = relative.equals(".") ? dir : repo;
            String name = (named.getFileName() == null ? named.toString() : named.getFileName().toString())
                    .replaceAll("\\.git$", "");
            items.add(new RemoteRepository(relative, NAMESPACE_ID, relative, name, repo.toUri(), null,
                    gitDir == null ? null : defaultBranch(gitDir).orElse(null), Visibility.PRIVATE, false,
                    lastModified(gitDir)));
        }
        return new Page<>(items, to < all.size() ? String.valueOf(to) : null, all.size());
    }

    @Override
    public Page<RemoteBranch> listBranches(GitConnectionSpec connection, String repositoryExternalId, PageRequest page) {
        Path dir = resolve(connection);
        Path gitDir = requireGitDir(dir, repositoryExternalId);
        TreeMap<String, String> branches = readBranches(gitDir);
        String defaultBranch = defaultBranch(gitDir).orElse(null);
        List<String> names = new ArrayList<>(branches.keySet());
        int from = Math.min(offset(page), names.size());
        int to = Math.min(from + page.size(), names.size());
        List<RemoteBranch> items = new ArrayList<>();
        for (String n : names.subList(from, to)) {
            items.add(new RemoteBranch(n, branches.get(n), n.equals(defaultBranch), false));
        }
        return new Page<>(items, to < names.size() ? String.valueOf(to) : null, names.size());
    }

    @Override
    public Optional<String> resolveHeadCommit(GitConnectionSpec connection, String repositoryExternalId, String branch) {
        Path dir = resolve(connection);
        return Optional.ofNullable(readBranches(requireGitDir(dir, repositoryExternalId)).get(branch));
    }

    // ------------------------------------------------------------------ filesystem

    /** Resolves the connection directory and checks it stays inside the root. */
    Path resolve(GitConnectionSpec connection) {
        if (root == null) {
            throw new GitProviderException(Kind.BLOCKED_BY_POLICY,
                    "Local repositories are disabled: set SAYTU_LOCAL_REPOS_ROOT and mount the directory read-only.");
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

    /** Repositories below {@code dir}, as sorted relative paths ("." when {@code dir} itself is one). */
    static List<String> findRepositories(Path dir) {
        List<String> result = new ArrayList<>();
        collect(dir, dir, 0, result);
        result.sort(String::compareTo);
        return result;
    }

    private static void collect(Path base, Path dir, int depth, List<String> out) {
        if (isRepository(dir)) {
            String rel = base.relativize(dir).toString().replace('\\', '/');
            out.add(rel.isEmpty() ? "." : rel);
            return;
        }
        if (depth >= MAX_DEPTH) {
            return;
        }
        try (DirectoryStream<Path> children = Files.newDirectoryStream(dir,
                p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) && !p.getFileName().toString().startsWith("."))) {
            for (Path child : children) {
                collect(base, child, depth + 1, out);
            }
        } catch (IOException e) {
            // unreadable directory: skipped
        }
    }

    static boolean isRepository(Path dir) {
        if (Files.isDirectory(dir.resolve(".git"), LinkOption.NOFOLLOW_LINKS)
                || Files.isRegularFile(dir.resolve(".git"), LinkOption.NOFOLLOW_LINKS)) {
            return true;
        }
        return isBare(dir);
    }

    private static boolean isBare(Path dir) {
        return Files.isRegularFile(dir.resolve("HEAD"), LinkOption.NOFOLLOW_LINKS)
                && Files.isDirectory(dir.resolve("objects"), LinkOption.NOFOLLOW_LINKS)
                && Files.isDirectory(dir.resolve("refs"), LinkOption.NOFOLLOW_LINKS);
    }

    private Path requireGitDir(Path dir, String relative) {
        if (relative.contains("..") || relative.startsWith("/") || relative.contains("\\")) {
            throw new GitProviderException(Kind.BLOCKED_BY_POLICY, "Invalid repository path");
        }
        Path repo = relative.equals(".") ? dir : dir.resolve(relative).normalize();
        if (!repo.startsWith(dir) || !isRepository(repo)) {
            throw new GitProviderException(Kind.NOT_FOUND, "Repository " + relative + " not found");
        }
        Path gitDir = gitDir(repo, dir);
        if (gitDir == null) {
            throw new GitProviderException(Kind.NOT_FOUND, "Git metadata of " + relative + " not readable");
        }
        return gitDir;
    }

    /**
     * Git directory of a repository: the repository itself (bare), its {@code .git} directory, or the
     * target of a {@code .git} file ({@code gitdir: ...}) when it stays inside {@code dir}.
     */
    static Path gitDir(Path repo, Path dir) {
        if (isBare(repo)) {
            return repo;
        }
        Path dotGit = repo.resolve(".git");
        if (Files.isDirectory(dotGit, LinkOption.NOFOLLOW_LINKS)) {
            return dotGit;
        }
        try {
            String content = Files.readString(dotGit, StandardCharsets.UTF_8).strip();
            if (!content.startsWith("gitdir:") || content.length() > 4096) {
                return null;
            }
            Path target = repo.resolve(content.substring("gitdir:".length()).strip()).toRealPath();
            return target.startsWith(dir.toRealPath()) && Files.isDirectory(target) ? target : null;
        } catch (IOException | java.nio.file.InvalidPathException e) {
            return null;
        }
    }

    static Optional<String> defaultBranch(Path gitDir) {
        try {
            String head = Files.readString(gitDir.resolve("HEAD"), StandardCharsets.UTF_8).strip();
            if (head.startsWith("ref: refs/heads/")) {
                return Optional.of(head.substring("ref: refs/heads/".length()));
            }
        } catch (IOException e) {
            // detached or unreadable HEAD
        }
        return Optional.empty();
    }

    /** Branch name → commit id, from loose refs (which take precedence) and packed-refs. */
    static TreeMap<String, String> readBranches(Path gitDir) {
        TreeMap<String, String> branches = new TreeMap<>();
        Path packed = gitDir.resolve("packed-refs");
        try {
            if (Files.isRegularFile(packed, LinkOption.NOFOLLOW_LINKS) && Files.size(packed) <= MAX_PACKED_REFS_BYTES) {
                try (BufferedReader reader = Files.newBufferedReader(packed, StandardCharsets.UTF_8)) {
                    String line;
                    while ((line = reader.readLine()) != null && branches.size() < MAX_REFS) {
                        if (line.startsWith("#") || line.startsWith("^")) {
                            continue;
                        }
                        int space = line.indexOf(' ');
                        if (space > 0 && line.startsWith("refs/heads/", space + 1)
                                && OBJECT_ID.matcher(line.substring(0, space)).matches()) {
                            branches.put(line.substring(space + 1 + "refs/heads/".length()), line.substring(0, space));
                        }
                    }
                }
            }
        } catch (IOException e) {
            // ignore unreadable packed-refs
        }
        Path heads = gitDir.resolve("refs").resolve("heads");
        if (Files.isDirectory(heads, LinkOption.NOFOLLOW_LINKS)) {
            try (var walk = Files.walk(heads, 32)) {
                walk.filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                        .limit(MAX_REFS)
                        .forEach(p -> {
                            try {
                                if (Files.size(p) > 200) {
                                    return;
                                }
                                String id = Files.readString(p, StandardCharsets.UTF_8).strip();
                                if (OBJECT_ID.matcher(id).matches()) {
                                    branches.put(heads.relativize(p).toString().replace('\\', '/'), id);
                                }
                            } catch (IOException e) {
                                // skip unreadable ref
                            }
                        });
            } catch (IOException e) {
                // ignore
            }
        }
        return branches;
    }

    private static Instant lastModified(Path gitDir) {
        if (gitDir == null) {
            return null;
        }
        try {
            return Files.readAttributes(gitDir, BasicFileAttributes.class).lastModifiedTime().toInstant();
        } catch (IOException e) {
            return null;
        }
    }

    private static int offset(PageRequest page) {
        if (page.cursor() == null) {
            return 0;
        }
        if (!page.cursor().matches("\\d{1,9}")) {
            throw new IllegalArgumentException("Invalid page cursor");
        }
        return Integer.parseInt(page.cursor());
    }
}
