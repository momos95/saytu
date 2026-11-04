package com.saytu.app.source;

import com.saytu.app.TestKeys;
import com.saytu.app.audit.AuditService;
import com.saytu.app.vault.TokenVault;
import com.saytu.app.vault.VaultProperties;
import com.saytu.app.web.ConflictException;
import com.saytu.core.domain.GitProviderType;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProvider;
import com.saytu.core.git.GitProvider.ConnectionTestResult;
import com.saytu.core.git.GitProviderException;
import com.saytu.git.provider.GitProviders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GitConnectionServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-04T10:00:00Z");

    private final GitConnectionRepository repository = mock(GitConnectionRepository.class);
    private final GitProviders providers = mock(GitProviders.class);
    private final GitProvider gitlab = mock(GitProvider.class);
    private final AuditService audit = mock(AuditService.class);
    private final TokenVault vault = new TokenVault(new VaultProperties(TestKeys.MASTER_KEY, List.of()));
    private GitConnectionService service;

    @BeforeEach
    void setUp() {
        when(providers.get(GitProviderType.GITLAB)).thenReturn(gitlab);
        when(repository.saveAndFlush(any())).thenAnswer(inv -> {
            GitConnectionEntity e = inv.getArgument(0);
            if (e.getId() == null) {
                ReflectionTestUtils.setField(e, "id", UUID.randomUUID());
            }
            return e;
        });
        service = new GitConnectionService(repository, vault, providers, audit, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static GitConnectionRequest request(String baseUrl, String token, Long version) {
        return new GitConnectionRequest("Corp GitLab", GitProviderType.GITLAB, baseUrl, null, null, token, false, null, version);
    }

    private GitConnectionEntity created(String token) {
        ArgumentCaptor<GitConnectionEntity> captor = ArgumentCaptor.forClass(GitConnectionEntity.class);
        service.create(request("https://gitlab.corp.sn/", token, null));
        verify(repository).saveAndFlush(captor.capture());
        GitConnectionEntity e = captor.getValue();
        when(repository.findById(e.getId())).thenReturn(Optional.of(e));
        return e;
    }

    @Test
    void createEncryptsTheTokenAndNeverReturnsIt() {
        GitConnectionEntity e = created("glpat-supersecret");
        assertThat(e.getBaseUrl()).isEqualTo("https://gitlab.corp.sn");
        assertThat(e.hasToken()).isTrue();
        assertThat(new String(e.getTokenCiphertext(), StandardCharsets.ISO_8859_1)).doesNotContain("supersecret");
        assertThat(GitConnectionView.of(e).toString()).doesNotContain("supersecret");
        verify(audit).record(eq(AuditService.CONNECTION_TOKEN_CHANGED), anyString(), anyString(), anyMap());
        verify(audit).record(eq(AuditService.CONNECTION_CREATED), anyString(), anyString(), anyMap());
    }

    @Test
    void duplicateNamesAreRejected() {
        when(repository.existsByName("Corp GitLab")).thenReturn(true);
        assertThatThrownBy(() -> service.create(request("https://gitlab.corp.sn", "t", null)))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void changingTheHostRequiresTheTokenAgain() {
        GitConnectionEntity e = created("glpat-supersecret");
        assertThatThrownBy(() -> service.update(e.getId(), request("https://attacker.example", null, e.getVersion())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("type the token again");
        GitConnectionView updated = service.update(e.getId(), request("https://attacker.example", "new-token", e.getVersion()));
        assertThat(updated.baseUrl()).isEqualTo("https://attacker.example");
    }

    @Test
    void staleVersionIsAConflict() {
        GitConnectionEntity e = created("t");
        assertThatThrownBy(() -> service.update(e.getId(), request("https://gitlab.corp.sn", null, 99L)))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void testDecryptsTheTokenForTheProviderAndRecordsTheOutcome() {
        GitConnectionEntity e = created("glpat-supersecret");
        ArgumentCaptor<GitConnectionSpec> spec = ArgumentCaptor.forClass(GitConnectionSpec.class);
        when(gitlab.testConnection(spec.capture())).thenAnswer(inv -> {
            assertThat(((GitConnectionSpec) inv.getArgument(0)).token().reveal()).isEqualTo("glpat-supersecret");
            return ConnectionTestResult.ok("awa", "17.11", List.of("read_api"), List.of("w"), NOW.plusSeconds(86_400));
        });

        ConnectionTestView view = service.test(e.getId());

        assertThat(view.success()).isTrue();
        assertThat(view.status()).isEqualTo("OK");
        assertThat(e.getLastTestStatus()).isEqualTo("OK");
        assertThat(e.getLastTestIdentity()).isEqualTo("awa");
        assertThat(e.getTokenExpiresAt()).isEqualTo(NOW.plusSeconds(86_400));
        assertThat(spec.getValue().token().isDestroyed()).as("token wiped after the call").isTrue();
    }

    @Test
    void failedTestIsRecordedWithItsKind() {
        GitConnectionEntity e = created("bad");
        when(gitlab.testConnection(any())).thenReturn(ConnectionTestResult.failure(
                new GitProviderException(GitProviderException.Kind.AUTHENTICATION_FAILED, "401")));
        ConnectionTestView view = service.test(e.getId());
        assertThat(view.success()).isFalse();
        assertThat(e.getLastTestStatus()).isEqualTo("AUTHENTICATION_FAILED");
    }

    @Test
    void localConnectionsTakeNoCredentials() {
        assertThatThrownBy(() -> GitConnectionService.validateCredentials(GitProviderType.LOCAL, null, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> GitConnectionService.validateCredentials(GitProviderType.GITHUB, "me", false))
                .hasMessageContaining("only used together with a token");
    }

    @Test
    void deleteIsAudited() {
        GitConnectionEntity e = created("t");
        service.delete(e.getId());
        verify(repository).delete(e);
        verify(audit).record(eq(AuditService.CONNECTION_DELETED), anyString(), eq(e.getId().toString()), anyMap());
        verify(audit, never()).record(eq(AuditService.CONNECTION_TESTED), anyString(), anyString(), anyMap());
    }
}
