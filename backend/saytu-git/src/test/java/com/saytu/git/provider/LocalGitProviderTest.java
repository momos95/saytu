package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProviderException.Kind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalGitProviderTest {

    private Path tmp;
    private Path root;
    private Path outside;

    @BeforeEach
    void setUp() throws IOException {
        tmp = Files.createTempDirectory("saytu-local");
        root = Files.createDirectories(tmp.resolve("srv-git"));
        outside = Files.createDirectories(tmp.resolve("secret"));
        Files.createDirectories(root.resolve("team-a/api/.git"));
        Path bare = Files.createDirectories(root.resolve("team-b/web.git"));
        Files.writeString(bare.resolve("HEAD"), "ref: refs/heads/main\n");
        Files.createDirectories(bare.resolve("objects"));
        Files.createDirectories(bare.resolve("refs"));
        Files.createDirectories(root.resolve("empty"));
    }

    @AfterEach
    void tearDown() throws IOException {
        try (Stream<Path> walk = Files.walk(tmp)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private GitConnectionSpec spec(Path dir) {
        return new GitConnectionSpec(GitProviderType.LOCAL, dir.toUri(), null, null, null, true);
    }

    @Test
    void countsWorkingTreesAndBareRepositories() {
        var r = new LocalGitProvider(root).testConnection(spec(root));
        assertTrue(r.success(), String.valueOf(r.errorMessage()));
        assertEquals("2 repositories found", r.serverVersion());
        assertTrue(r.warnings().isEmpty());
    }

    @Test
    void emptyDirectoryWarns() {
        var r = new LocalGitProvider(root).testConnection(spec(root.resolve("empty")));
        assertTrue(r.success());
        assertTrue(r.warnings().getFirst().startsWith("No Git repository"));
    }

    @Test
    void pathsOutsideTheRootAreRefused() {
        var r = new LocalGitProvider(root).testConnection(spec(outside));
        assertFalse(r.success());
        assertEquals(Kind.BLOCKED_BY_POLICY, r.errorKind());
        var traversal = new LocalGitProvider(root).testConnection(spec(root.resolve("../secret")));
        assertEquals(Kind.BLOCKED_BY_POLICY, traversal.errorKind());
    }

    @Test
    void symbolicLinksCannotEscapeTheRoot() throws IOException {
        Path link = root.resolve("escape");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (UnsupportedOperationException | IOException e) {
            return; // filesystem without symlinks
        }
        var r = new LocalGitProvider(root).testConnection(spec(link));
        assertEquals(Kind.BLOCKED_BY_POLICY, r.errorKind());
    }

    @Test
    void disabledWithoutRootAndMissingDirectories() {
        assertEquals(Kind.BLOCKED_BY_POLICY, new LocalGitProvider(null).testConnection(spec(root)).errorKind());
        assertEquals(Kind.NOT_FOUND, new LocalGitProvider(root).testConnection(spec(root.resolve("nope"))).errorKind());
    }
}
