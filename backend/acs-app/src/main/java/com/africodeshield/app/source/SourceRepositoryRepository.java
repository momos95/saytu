package com.africodeshield.app.source;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SourceRepositoryRepository extends JpaRepository<SourceRepositoryEntity, UUID>,
        JpaSpecificationExecutor<SourceRepositoryEntity> {

    Page<SourceRepositoryEntity> findByNamespaceId(UUID namespaceId, Pageable pageable);

    List<SourceRepositoryEntity> findByNamespaceId(UUID namespaceId);

    List<SourceRepositoryEntity> findByConnectionId(UUID connectionId);

    Optional<SourceRepositoryEntity> findByConnectionIdAndExternalId(UUID connectionId, String externalId);

    List<SourceRepositoryEntity> findBySelectedTrueAndArchivedFalse();

    long countBySelectedTrue();

    /** [namespace id, repositories, selected repositories], removed repositories excluded. */
    @Query("select r.namespace.id, count(r), sum(case when r.selected = true then 1 else 0 end) "
            + "from SourceRepositoryEntity r where r.connection.id = :connectionId and r.removedAt is null "
            + "and r.namespace is not null group by r.namespace.id")
    List<Object[]> countsByNamespace(@Param("connectionId") UUID connectionId);

    /** [branch mode, count] of the current scan targets. */
    @Query("select r.branchMode, count(r) from SourceRepositoryEntity r join r.namespace n join r.connection c "
            + "where r.removedAt is null and r.archived = false and n.selected = true and n.removedAt is null "
            + "and c.enabled = true and (n.includeAllRepositories = true or r.selected = true) group by r.branchMode")
    List<Object[]> scanTargetCountsByBranchMode();
}
