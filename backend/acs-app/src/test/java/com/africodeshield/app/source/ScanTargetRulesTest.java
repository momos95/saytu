package com.africodeshield.app.source;

import com.africodeshield.core.domain.GitProviderType;
import com.africodeshield.core.domain.NamespaceKind;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link SourceRepositoryEntity#isScanTarget()}: what ends up audited. */
class ScanTargetRulesTest {

    private final GitConnectionEntity connection = new GitConnectionEntity("c", GitProviderType.GITHUB, "https://github.com", "a");
    private final GitNamespaceEntity org = new GitNamespaceEntity(connection, "acme", NamespaceKind.ORGANIZATION, "acme", "Acme");

    private SourceRepositoryEntity repo() {
        SourceRepositoryEntity r = new SourceRepositoryEntity(connection, "acme/api", "acme/api", "api",
                "https://github.com/acme/api.git");
        r.setNamespace(org);
        return r;
    }

    @Test
    void namespaceMustBeSelected() {
        SourceRepositoryEntity r = repo();
        r.setSelected(true);
        assertThat(r.isScanTarget()).isFalse();
        org.setSelected(true);
        assertThat(r.isScanTarget()).isTrue();
    }

    @Test
    void includeAllCoversUnselectedRepositories() {
        org.setSelected(true);
        SourceRepositoryEntity r = repo();
        assertThat(r.isScanTarget()).isFalse();
        org.setIncludeAllRepositories(true);
        assertThat(r.isScanTarget()).isTrue();
    }

    @Test
    void archivedRemovedOrDisabledAreNeverTargets() {
        org.setSelected(true);
        org.setIncludeAllRepositories(true);
        SourceRepositoryEntity archived = repo();
        archived.setArchived(true);
        assertThat(archived.isScanTarget()).isFalse();
        SourceRepositoryEntity removed = repo();
        removed.markRemoved(Instant.now());
        assertThat(removed.isScanTarget()).isFalse();
        SourceRepositoryEntity ok = repo();
        connection.setEnabled(false);
        assertThat(ok.isScanTarget()).isFalse();
    }

    @Test
    void cloneUrlsAndBranchNamesAreValidated() {
        assertThatThrownBy(() -> new SourceRepositoryEntity(connection, "x", "x", "x", "https://user:pw@github.com/x.git"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RepositoryBranchEntity(repo(), "--upload-pack=x"))
                .hasMessageContaining("must not start with '-'");
    }
}
