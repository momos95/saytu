package com.saytu.app.source;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface GitNamespaceRepository extends JpaRepository<GitNamespaceEntity, UUID> {

    List<GitNamespaceEntity> findByConnectionIdOrderByFullPath(UUID connectionId);

    List<GitNamespaceEntity> findByConnectionId(UUID connectionId);

    Optional<GitNamespaceEntity> findByConnectionIdAndExternalId(UUID connectionId, String externalId);

    List<GitNamespaceEntity> findBySelectedTrue();

    @Query("select count(n) from GitNamespaceEntity n where n.selected = true and n.removedAt is null "
            + "and n.connection.enabled = true")
    long countActiveSelected();
}
