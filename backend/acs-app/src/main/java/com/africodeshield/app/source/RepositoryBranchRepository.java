package com.africodeshield.app.source;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface RepositoryBranchRepository extends JpaRepository<RepositoryBranchEntity, UUID> {

    List<RepositoryBranchEntity> findByRepositoryIdOrderByName(UUID repositoryId);

    List<RepositoryBranchEntity> findByRepositoryIdAndEnabledTrue(UUID repositoryId);
}
