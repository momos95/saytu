package com.africodeshield.core.git;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BranchNamesTest {

    @Test
    void acceptsUsualBranchNames() {
        for (String ok : List.of("main", "master", "develop", "feature/ABC-12_login", "release/2026.11", "hotfix-ü", "v1.2.3")) {
            assertTrue(BranchNames.isValid(ok), ok);
        }
    }

    @Test
    void rejectsWhatGitRejectsAndInjectionAttempts() {
        for (String bad : List.of("", "-x", "--upload-pack=evil", "a..b", "a b", "a~1", "a^", "a:b", "a?", "a*", "a[",
                "a\\b", "a@{1}", "@", "HEAD", "/main", "main/", "a//b", "main.", "x.lock", "feat/.hidden", "a\u0000b",
                "a\nb", "x".repeat(256))) {
            assertFalse(BranchNames.isValid(bad), bad);
        }
    }

    @Test
    void requireExplains() {
        var e = assertThrows(IllegalArgumentException.class, () -> BranchNames.require("-rf"));
        assertTrue(e.getMessage().contains("must not start with '-'"));
        var ctl = assertThrows(IllegalArgumentException.class, () -> BranchNames.require("a\nb"));
        assertFalse(ctl.getMessage().contains("\n"));
    }
}
