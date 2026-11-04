package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProvider.PageRequest;
import com.saytu.core.git.GitProviderException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalDiscoveryTest {

    private static final String A = "a".repeat(40);
    private static final String B = "b".repeat(40);
    private static final String C = "c".repeat(40);

    private Path tmp;
    private Path root;
    private LocalGitProvider provider;
    private GitConnectionSpec spec;

    @BeforeEach
    void setUp() throws IOException {
        tmp = Files.createTempDirectory("saytu-local-disc");
        root = Files.createDirectories(tmp.resolve("srv-git"));
        // working tree with loose and packed refs
        Path api = Files.createDirectories(root.resolve("team/api/.git"));
        Files.writeString(api.resolve("HEAD"), "ref: refs/heads/main\n");
        Files.createDirectories(api.resolve("refs/heads/feature"));
        Files.writeString(api.resolve("refs/heads/main"), A + "\n");
        Files.writeString(api.resolve("refs/heads/feature/login"), B + "\n");
        Files.writeString(api.resolve("packed-refs"), "# pack-refs with: peeled fully-peeled sorted\n"
                + C + " refs/heads/main\n" + C + " refs/heads/develop\n^" + A + "\n" + C + " refs/tags/v1\n");
        // bare repository, packed refs only
        Path bare = Files.createDirectories(root.resolve("web.git"));
        Files.writeString(bare.resolve("HEAD"), "ref: refs/heads/master\n");
        Files.createDirectories(bare.resolve("objects"));
        Files.createDirectories(bare.resolve("refs/heads"));
        Files.writeString(bare.resolve("packed-refs"), A + " refs/heads/master\n");
        provider = new LocalGitProvider(root);
        spec = new GitConnectionSpec(GitProviderType.LOCAL, root.toUri(), null, null, null, true);
    }

    @AfterEach
    void tearDown() throws IOException {
        try (Stream<Path> walk = Files.walk(tmp)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Test
    void oneNamespaceAndRepositoriesWithDefaultBranch() {
        assertEquals(LocalGitProvider.NAMESPACE_ID, provider.listNamespaces(spec, PageRequest.first(10)).items().getFirst().externalId());
        var repos = provider.listRepositories(spec, ".", PageRequest.first(10)).items();
        assertEquals(List.of("team/api", "web.git"), repos.stream().map(r -> r.externalId()).toList());
        assertEquals("main", repos.getFirst().defaultBranch());
        assertEquals("master", repos.get(1).defaultBranch());
        assertEquals("web", repos.get(1).name());
        assertTrue(repos.getFirst().cloneUrl().toString().startsWith("file:"));
    }

    @Test
    void branchesMergeLooseAndPackedRefsLooseWinning() {
        var branches = provider.listBranches(spec, "team/api", PageRequest.first(100)).items();
        assertEquals(List.of("develop", "feature/login", "main"), branches.stream().map(b -> b.name()).toList());
        assertEquals(A, branches.get(2).headCommitSha(), "loose ref overrides packed-refs");
        assertTrue(branches.get(2).isDefault());
        assertEquals(Optional.of(C), provider.resolveHeadCommit(spec, "team/api", "develop"));
        assertEquals(Optional.empty(), provider.resolveHeadCommit(spec, "team/api", "v1"), "tags are not branches");
    }

    @Test
    void paginationByOffset() {
        var first = provider.listRepositories(spec, ".", PageRequest.first(1));
        assertEquals("1", first.nextCursor());
        var second = provider.listRepositories(spec, ".", new PageRequest("1", 1));
        assertEquals("web.git", second.items().getFirst().externalId());
        assertEquals(null, second.nextCursor());
    }

    @Test
    void repositoryPathsCannotEscape() {
        assertThrows(GitProviderException.class, () -> provider.listBranches(spec, "../secret", PageRequest.first(10)));
        assertThrows(GitProviderException.class, () -> provider.listBranches(spec, "/etc", PageRequest.first(10)));
        assertThrows(GitProviderException.class, () -> provider.listBranches(spec, "missing", PageRequest.first(10)));
    }

    @Test
    void gitFilePointingOutsideTheRootIsIgnored() throws IOException {
        Path outside = Files.createDirectories(tmp.resolve("elsewhere/.git"));
        Files.writeString(outside.resolve("HEAD"), "ref: refs/heads/main\n");
        Path worktree = Files.createDirectories(root.resolve("linked"));
        Files.writeString(worktree.resolve(".git"), "gitdir: " + outside + "\n");
        assertEquals(null, LocalGitProvider.gitDir(worktree, root.toRealPath()));
        assertThrows(GitProviderException.class, () -> provider.listBranches(spec, "linked", PageRequest.first(10)));
    }
}
