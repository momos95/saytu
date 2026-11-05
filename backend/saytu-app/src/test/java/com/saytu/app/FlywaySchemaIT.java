package com.saytu.app;

import com.saytu.app.scanner.ScannerConfigRepository;
import com.saytu.app.source.GitConnectionEntity;
import com.saytu.app.source.GitConnectionRepository;
import com.saytu.app.source.GitNamespaceEntity;
import com.saytu.app.source.GitNamespaceRepository;
import com.saytu.app.source.SourceRepositoryEntity;
import com.saytu.app.source.SourceRepositoryRepository;
import com.saytu.core.domain.GitProviderType;
import com.saytu.core.domain.NamespaceKind;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Starts the full application against a real PostgreSQL (Testcontainers):
 * Flyway applies the migrations and Hibernate's {@code ddl-auto=validate} proves that the JPA
 * entities match the schema. Requires Docker; run with {@code mvn verify}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = TestKeys.MASTER_KEY_PROPERTY)
@Testcontainers
class FlywaySchemaIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    ScannerConfigRepository scannerConfigs;
    @Autowired
    GitConnectionRepository connections;
    @Autowired
    GitNamespaceRepository namespaces;
    @Autowired
    SourceRepositoryRepository repositories;
    @Autowired
    JdbcTemplate jdbc;

    @Test
    void migrationSeedsAllScannersWithDependencyCheckDisabled() {
        assertThat(scannerConfigs.findAll()).hasSize(10);
        assertThat(scannerConfigs.findById("dependency-check")).get()
                .satisfies(s -> assertThat(s.isEnabled()).isFalse());
        assertThat(scannerConfigs.findById("trivy")).get()
                .satisfies(s -> assertThat(s.toResourceLimits().timeout().toSeconds()).isEqualTo(900));
    }

    @Test
    void persistsConnectionNamespaceAndRepository() {
        var connection = connections.save(new GitConnectionEntity("gitlab-it-" + System.nanoTime(),
                GitProviderType.GITLAB, "https://gitlab.example.org", "it"));
        var group = namespaces.save(new GitNamespaceEntity(connection, "7", NamespaceKind.GROUP, "acme", "Acme"));
        var repo = new SourceRepositoryEntity(connection, "42", "acme/api", "api",
                "https://gitlab.example.org/acme/api.git");
        repo.setNamespace(group);
        repositories.save(repo);

        assertThat(connection.getCreatedAt()).isNotNull();
        assertThat(repositories.findByConnectionIdAndExternalId(connection.getId(), "42")).isPresent();
    }

    @Test
    void databaseRejectsCloneUrlsWithCredentials() {
        var connection = connections.save(new GitConnectionEntity("gh-it-" + System.nanoTime(),
                GitProviderType.GITHUB, "https://github.com", "it"));
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO source_repository (connection_id, external_id, full_name, name, clone_url)
                VALUES (?, '1', 'o/r', 'r', 'https://x-access-token:ghp_secret@github.com/o/r.git')""",
                connection.getId()))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void auditTrailIsAppendOnly() {
        jdbc.update("INSERT INTO audit_event (actor_subject, action) VALUES ('it', 'TEST')");
        assertThatThrownBy(() -> jdbc.update("DELETE FROM audit_event"))
                .hasMessageContaining("append-only");
    }
}
