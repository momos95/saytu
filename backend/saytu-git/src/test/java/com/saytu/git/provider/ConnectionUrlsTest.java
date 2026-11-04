package com.saytu.git.provider;

import com.saytu.core.domain.GitProviderType;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectionUrlsTest {

    @Test
    void defaultsAndNormalisation() {
        assertEquals("https://gitlab.com", ConnectionUrls.normalizeBaseUrl(GitProviderType.GITLAB, " ").toString());
        assertEquals("https://github.com", ConnectionUrls.normalizeBaseUrl(GitProviderType.GITHUB, null).toString());
        assertEquals("https://gitlab.corp.sn:8443/gitlab",
                ConnectionUrls.normalizeBaseUrl(GitProviderType.GITLAB, "HTTPS://GitLab.Corp.SN:8443/gitlab//").toString());
        assertEquals("file:///srv/git/team-a",
                ConnectionUrls.normalizeBaseUrl(GitProviderType.LOCAL, "/srv/git/team-a/").toString());
        assertEquals("file:///srv/git", ConnectionUrls.normalizeBaseUrl(GitProviderType.LOCAL, "file:///srv/git").toString());
        assertNull(ConnectionUrls.normalizeApiUrl(GitProviderType.GITHUB, ""));
    }

    @Test
    void rejectsDangerousOrInvalidUrls() {
        for (String bad : new String[]{"ftp://x", "https://user:pass@git.example", "https:///nohost",
                "https://git.example/?x=1", "https://git.example/#a", "javascript:alert(1)", "git.example"}) {
            assertThrows(IllegalArgumentException.class, () -> ConnectionUrls.normalizeBaseUrl(GitProviderType.GITLAB, bad), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> ConnectionUrls.normalizeBaseUrl(GitProviderType.BITBUCKET_DATA_CENTER, ""));
        assertThrows(IllegalArgumentException.class, () -> ConnectionUrls.normalizeBaseUrl(GitProviderType.LOCAL, "relative/path"));
        assertThrows(IllegalArgumentException.class, () -> ConnectionUrls.normalizeBaseUrl(GitProviderType.LOCAL, "https://x"));
        assertThrows(IllegalArgumentException.class, () -> ConnectionUrls.normalizeApiUrl(GitProviderType.LOCAL, "/x"));
    }

    @Test
    void tokenMustBeRetypedWhenTheHostChanges() {
        URI a = URI.create("https://gitlab.corp.sn");
        assertFalse(ConnectionUrls.tokenReentryRequired(a, null, URI.create("https://gitlab.corp.sn:443/sub"), null));
        assertTrue(ConnectionUrls.tokenReentryRequired(a, null, URI.create("https://attacker.example"), null));
        assertTrue(ConnectionUrls.tokenReentryRequired(a, null, URI.create("http://gitlab.corp.sn"), null));
        assertTrue(ConnectionUrls.tokenReentryRequired(a, null, a, URI.create("https://other.example/api/v4")));
        assertTrue(ConnectionUrls.tokenReentryRequired(a, null, URI.create("https://gitlab.corp.sn:8443"), null));
    }
}
