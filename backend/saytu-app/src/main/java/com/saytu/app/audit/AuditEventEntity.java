package com.saytu.app.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;

/** Append-only audit trail row (the table rejects UPDATE and DELETE with a trigger). */
@Entity
@Immutable
@Table(name = "audit_event")
public class AuditEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Column(name = "actor_subject", nullable = false, updatable = false)
    private String actorSubject;

    @Column(name = "actor_username", updatable = false)
    private String actorUsername;

    @Column(nullable = false, length = 64, updatable = false)
    private String action;

    @Column(name = "target_type", length = 64, updatable = false)
    private String targetType;

    @Column(name = "target_id", updatable = false)
    private String targetId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb", updatable = false)
    private Map<String, Object> details;

    @Column(name = "client_ip", length = 64, updatable = false)
    private String clientIp;

    protected AuditEventEntity() {
        // JPA
    }

    public AuditEventEntity(Instant occurredAt, String actorSubject, String actorUsername, String action,
                            String targetType, String targetId, Map<String, Object> details, String clientIp) {
        this.occurredAt = occurredAt;
        this.actorSubject = actorSubject;
        this.actorUsername = actorUsername;
        this.action = action;
        this.targetType = targetType;
        this.targetId = targetId;
        this.details = details == null ? Map.of() : Map.copyOf(details);
        this.clientIp = clientIp;
    }

    public Long getId() {
        return id;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public String getActorSubject() {
        return actorSubject;
    }

    public String getActorUsername() {
        return actorUsername;
    }

    public String getAction() {
        return action;
    }

    public String getTargetType() {
        return targetType;
    }

    public String getTargetId() {
        return targetId;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public String getClientIp() {
        return clientIp;
    }
}
