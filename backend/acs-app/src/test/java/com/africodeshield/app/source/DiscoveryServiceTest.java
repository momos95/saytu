package com.africodeshield.app.source;

import com.africodeshield.app.audit.AuditService;
import com.africodeshield.app.vault.TokenVault;
import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.domain.NamespaceKind;
import com.africodeshield.core.git.GitProvider.Namespace;
import com.africodeshield.core.git.GitProvider.RemoteRepository;
import com.africodeshield.core.git.GitProvider.Visibility;
import com.africodeshield.core.git.GitProviderException;
import com.africodeshield.git.provider.GitProviders;
import com.africodeshield.git.provider.PageCollector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Merge rules of the synchronisation, without database nor network. */
class DiscoveryServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-04T16:00:00Z");

    private final GitConnectionRepository connections = mock(GitConnectionRepository.class);
    private final GitNamespaceRepository namespaces = mock(GitNamespaceRepository.class);
    private final SourceRepositoryRepository repositories = mock(SourceRepositoryRepository.class);
    private final List<GitNamespaceEntity> storedNamespaces = new ArrayList<>();
    private final List<SourceRepositoryEntity> storedRepositories = new ArrayList<>();
    private GitConnectionEntity connection;
    private DiscoveryService service;

    @BeforeEach
    void setUp() {
        connection = new GitConnectionEntity("gl", GitProviderType.GITLAB, "https://gitlab.com", "admin");
        ReflectionTestUtils.setField(connection, "id", UUID.randomUUID());
        when(connections.findById(connection.getId())).thenReturn(Optional.of(connection));
        when(namespaces.findByConnectionId(connection.getId())).thenAnswer(inv -> List.copyOf(storedNamespaces));
        when(namespaces.save(any())).thenAnswer(inv -> {
            GitNamespaceEntity e = inv.getArgument(0);
            if (e.getId() == null) {
                ReflectionTestUtils.setField(e, "id", UUID.randomUUID());
                storedNamespaces.add(e);
            }
            return e;
        });
        when(repositories.save(any())).thenAnswer(inv -> {
            SourceRepositoryEntity e = inv.getArgument(0);
            if (e.getId() == null) {
                ReflectionTestUtils.setField(e, "id", UUID.randomUUID());
                storedRepositories.add(e);
            }
            return e;
        });
        service = new DiscoveryService(connections, namespaces, repositories, mock(TokenVault.class),
                mock(GitProviders.class), mock(AuditService.class), mock(TransactionTemplate.class),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static Namespace ns(String id, String path, String parent) {
        return new Namespace(id, parent == null ? NamespaceKind.GROUP : NamespaceKind.SUBGROUP, path, path, parent, null);
    }

    private static RemoteRepository repo(String id, String fullName) {
        return new RemoteRepository(id, "10", fullName, fullName, URI.create("https://gitlab.com/" + fullName + ".git"),
                null, "main", Visibility.PRIVATE, false, null);
    }

    @Test
    void addsNamespacesAndLinksParents() {
        var result = service.mergeNamespaces(connection.getId(),
                new PageCollector.Result<>(List.of(ns("10", "acme", null), ns("11", "acme/pay", "10")), false, null));
        assertThat(result.status()).isEqualTo("OK");
        assertThat(result.added()).isEqualTo(2);
        GitNamespaceEntity sub = storedNamespaces.stream().filter(n -> n.getExternalId().equals("11")).findFirst().orElseThrow();
        assertThat(sub.getParent().getExternalId()).isEqualTo("10");
        assertThat(connection.getLastDiscoveryStatus()).isEqualTo("OK");
    }

    @Test
    void keepsSelectionAndFlagsMissingOnlyAfterACompleteListing() {
        service.mergeNamespaces(connection.getId(),
                new PageCollector.Result<>(List.of(ns("10", "acme", null), ns("20", "ops", null)), false, null));
        GitNamespaceEntity acme = storedNamespaces.getFirst();
        acme.setSelected(true);
        GitNamespaceEntity ops = storedNamespaces.get(1);

        // partial listing (rate limit): nothing is flagged removed
        var partial = service.mergeNamespaces(connection.getId(), new PageCollector.Result<>(List.of(ns("10", "acme", null)),
                false, new GitProviderException(GitProviderException.Kind.RATE_LIMITED, "slow down")));
        assertThat(partial.status()).isEqualTo("RATE_LIMITED");
        assertThat(ops.isRemoved()).isFalse();

        // complete listing without "ops": flagged, not deleted; "acme" keeps its selection
        var complete = service.mergeNamespaces(connection.getId(), new PageCollector.Result<>(List.of(ns("10", "acme", null)), false, null));
        assertThat(complete.removed()).isEqualTo(1);
        assertThat(ops.isRemoved()).isTrue();
        assertThat(acme.isSelected()).isTrue();

        // reappears: no longer removed
        service.mergeNamespaces(connection.getId(),
                new PageCollector.Result<>(List.of(ns("10", "acme", null), ns("20", "ops", null)), false, null));
        assertThat(ops.isRemoved()).isFalse();
    }

    @Test
    void manuallyAddedNamespacesAreNeverFlaggedRemoved() {
        GitNamespaceEntity manual = new GitNamespaceEntity(connection, "kubernetes", NamespaceKind.ORGANIZATION, "kubernetes", "k8s");
        manual.setAddedManually(true);
        storedNamespaces.add(manual);
        service.mergeNamespaces(connection.getId(), new PageCollector.Result<>(List.of(), false, null));
        assertThat(manual.isRemoved()).isFalse();
    }

    @Test
    void repositoriesAreMergedPerNamespace() {
        GitNamespaceEntity group = new GitNamespaceEntity(connection, "10", NamespaceKind.GROUP, "acme", "Acme");
        UUID groupId = UUID.randomUUID();
        ReflectionTestUtils.setField(group, "id", groupId);
        when(namespaces.findById(groupId)).thenReturn(Optional.of(group));
        when(repositories.findByNamespaceId(groupId)).thenAnswer(inv -> List.copyOf(storedRepositories));

        var first = service.mergeRepositories(groupId, new PageCollector.Result<>(
                List.of(repo("1", "acme/api"), repo("2", "acme/web")), false, null));
        assertThat(first.added()).isEqualTo(2);
        storedRepositories.getFirst().setSelected(true);

        var truncated = service.mergeRepositories(groupId, new PageCollector.Result<>(List.of(repo("1", "acme/api")), true, null));
        assertThat(truncated.status()).isEqualTo("PARTIAL");
        assertThat(storedRepositories.get(1).isRemoved()).as("truncated listing never removes").isFalse();

        service.mergeRepositories(groupId, new PageCollector.Result<>(List.of(repo("1", "acme/api-renamed")), false, null));
        assertThat(storedRepositories.getFirst().getFullName()).isEqualTo("acme/api-renamed");
        assertThat(storedRepositories.getFirst().isSelected()).isTrue();
        assertThat(storedRepositories.get(1).isRemoved()).isTrue();
        assertThat(group.getRepositoriesSyncStatus()).isEqualTo("OK");
    }
}
