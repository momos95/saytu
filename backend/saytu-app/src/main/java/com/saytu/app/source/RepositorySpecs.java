package com.saytu.app.source;

import jakarta.persistence.criteria.Join;
import org.springframework.data.jpa.domain.Specification;

import java.util.Locale;
import java.util.UUID;

/** Composable filters for repository listings (avoids nullable JPQL parameters, which PostgreSQL cannot type). */
final class RepositorySpecs {

    private RepositorySpecs() {
    }

    static Specification<SourceRepositoryEntity> inNamespace(UUID namespaceId) {
        return (root, query, cb) -> cb.equal(root.get("namespace").get("id"), namespaceId);
    }

    static Specification<SourceRepositoryEntity> notRemoved() {
        return (root, query, cb) -> cb.isNull(root.get("removedAt"));
    }

    static Specification<SourceRepositoryEntity> selected(boolean selected) {
        return (root, query, cb) -> cb.equal(root.get("selected"), selected);
    }

    /** Case-insensitive "contains" on the full name; LIKE wildcards in the input are escaped. */
    static Specification<SourceRepositoryEntity> nameContains(String text) {
        String escaped = text.strip().toLowerCase(Locale.ROOT)
                .replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return (root, query, cb) -> cb.like(cb.lower(root.get("fullName")), "%" + escaped + "%", '\\');
    }

    /** Same rule as {@link SourceRepositoryEntity#isScanTarget()}, evaluated by the database. */
    static Specification<SourceRepositoryEntity> scanTarget() {
        return (root, query, cb) -> {
            Join<Object, Object> ns = root.join("namespace");
            Join<Object, Object> connection = root.join("connection");
            return cb.and(
                    cb.isNull(root.get("removedAt")),
                    cb.isFalse(root.get("archived")),
                    cb.isTrue(ns.get("selected")),
                    cb.isNull(ns.get("removedAt")),
                    cb.isTrue(connection.get("enabled")),
                    cb.or(cb.isTrue(ns.get("includeAllRepositories")), cb.isTrue(root.get("selected"))));
        };
    }
}
