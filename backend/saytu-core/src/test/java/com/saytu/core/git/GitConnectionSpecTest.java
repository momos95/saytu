package com.saytu.core.git;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.security.SensitiveValue;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitConnectionSpecTest {

    @Test
    void toStringMasksToken() {
        var spec = new GitConnectionSpec(GitProviderType.GITLAB, URI.create("https://gitlab.example.org"), null,
                null, SensitiveValue.of("glpat-verysecretvalue1234"), true);
        assertFalse(spec.toString().contains("verysecret"));
        assertTrue(spec.toString().contains(SensitiveValue.MASK));
        assertTrue(spec.hasToken());
    }

    @Test
    void rejectsCredentialsInUrl() {
        assertThrows(IllegalArgumentException.class, () -> new GitConnectionSpec(GitProviderType.GITHUB,
                URI.create("https://user:pass@github.example.org"), null, null, null, true));
    }

    @Test
    void rejectsNonHttpSchemesForRemoteProviders() {
        assertThrows(IllegalArgumentException.class, () -> new GitConnectionSpec(GitProviderType.GITHUB,
                URI.create("ftp://github.example.org"), null, null, null, true));
    }

    @Test
    void localProviderRequiresFileUri() {
        assertThrows(IllegalArgumentException.class, () -> new GitConnectionSpec(GitProviderType.LOCAL,
                URI.create("https://x"), null, null, null, true));
        assertDoesNotThrow(() -> new GitConnectionSpec(GitProviderType.LOCAL,
                URI.create("file:///srv/git"), null, null, null, true));
    }

    @Test
    void destroyedOrMissingTokenMeansNoToken() {
        var token = SensitiveValue.of("t0ken");
        var spec = new GitConnectionSpec(GitProviderType.GITHUB, URI.create("https://github.com"), null, null, token, true);
        token.destroy();
        assertFalse(spec.hasToken());
        assertFalse(new GitConnectionSpec(GitProviderType.GITHUB, URI.create("https://github.com"), null, null, null, true).hasToken());
    }

    @Test
    void pageRequestBounds() {
        assertThrows(IllegalArgumentException.class, () -> GitProvider.PageRequest.first(0));
        assertThrows(IllegalArgumentException.class, () -> GitProvider.PageRequest.first(101));
        assertDoesNotThrow(() -> GitProvider.PageRequest.first(100));
    }
}
