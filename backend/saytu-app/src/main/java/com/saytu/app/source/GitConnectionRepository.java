package com.saytu.app.source;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface GitConnectionRepository extends JpaRepository<GitConnectionEntity, UUID> {

    Optional<GitConnectionEntity> findByName(String name);

    boolean existsByName(String name);
}
