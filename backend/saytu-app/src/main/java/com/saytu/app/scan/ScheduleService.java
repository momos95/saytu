package com.saytu.app.scan;

import com.saytu.app.audit.AuditService;
import com.saytu.app.web.ResourceNotFoundException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** Audit schedules (cron): administration side. The worker fires them ({@link ScheduleTrigger}). */
@Service
public class ScheduleService {

    static final int MAX_TARGETS = 1000;

    private final NamedParameterJdbcTemplate jdbc;
    private final AuditService audit;
    private final Clock clock;

    public ScheduleService(NamedParameterJdbcTemplate jdbc, AuditService audit, Clock clock) {
        this.jdbc = jdbc;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * @param scope ALL_SELECTED (every repository selected for audit), REPOSITORIES or NAMESPACES (targets given)
     */
    public record ScheduleRequest(String name, String cronExpression, String timeZone, String scope, Boolean enabled,
                                  List<UUID> repositoryIds, List<UUID> namespaceIds) {
    }

    public record ScheduleView(UUID id, String name, String cronExpression, String timeZone, String scope, boolean enabled,
                               Instant nextFireAt, Instant lastFiredAt, UUID lastRunId, String lastRunStatus,
                               String lastOutcome, List<UUID> repositoryIds, List<UUID> namespaceIds, String createdBy,
                               Instant createdAt, Instant updatedAt) {
    }

    /** Validated request: normalized cron, zone, scope and targets. */
    record Valid(String name, String cron, ZoneId zone, String scope, boolean enabled, List<UUID> targets) {
    }

    static Valid validate(ScheduleRequest r, Instant now) {
        if (r == null) {
            throw new IllegalArgumentException("Requête vide");
        }
        String name = r.name() == null ? "" : r.name().strip();
        if (name.isEmpty() || name.length() > 120) {
            throw new IllegalArgumentException("Nom obligatoire (120 caractères au plus)");
        }
        String cron = CronSchedules.normalize(r.cronExpression());
        ZoneId zone = CronSchedules.zone(r.timeZone());
        CronSchedules.checkInterval(cron, zone, now);
        String scope = r.scope() == null ? "ALL_SELECTED" : r.scope().strip().toUpperCase(Locale.ROOT);
        List<UUID> targets = switch (scope) {
            case "ALL_SELECTED" -> List.of();
            case "REPOSITORIES" -> distinct(r.repositoryIds(), "dépôt");
            case "NAMESPACES" -> distinct(r.namespaceIds(), "organisation");
            default -> throw new IllegalArgumentException("Périmètre inconnu : " + r.scope());
        };
        return new Valid(name, cron, zone, scope, r.enabled() == null || r.enabled(), targets);
    }

    private static List<UUID> distinct(List<UUID> ids, String what) {
        Set<UUID> set = new LinkedHashSet<>(ids == null ? List.of() : ids);
        set.remove(null);
        if (set.isEmpty()) {
            throw new IllegalArgumentException("Choisissez au moins un(e) " + what);
        }
        if (set.size() > MAX_TARGETS) {
            throw new IllegalArgumentException("Trop de cibles (" + MAX_TARGETS + " au plus)");
        }
        return List.copyOf(set);
    }

    @Transactional(readOnly = true)
    public List<ScheduleView> list() {
        return jdbc.query(AutomationSql.LIST_SCHEDULES, new MapSqlParameterSource(), (rs, i) -> view(rs));
    }

    @Transactional(readOnly = true)
    public ScheduleView get(UUID id) {
        return jdbc.query(AutomationSql.GET_SCHEDULE, new MapSqlParameterSource("id", id), (rs, i) -> view(rs))
                .stream().findFirst().orElseThrow(() -> new ResourceNotFoundException("Schedule " + id + " not found"));
    }

    @Transactional
    public ScheduleView create(ScheduleRequest request) {
        Valid v = validate(request, clock.instant());
        UUID id = UUID.randomUUID();
        jdbc.update(AutomationSql.INSERT_SCHEDULE, params(id, v).addValue("user", currentUser()));
        saveTargets(id, v);
        audit.record("SCHEDULE_CREATED", "scan_schedule", id.toString(), Map.of("name", v.name(), "cron", v.cron()));
        return get(id);
    }

    @Transactional
    public ScheduleView update(UUID id, ScheduleRequest request) {
        get(id);
        Valid v = validate(request, clock.instant());
        jdbc.update(AutomationSql.UPDATE_SCHEDULE, params(id, v));
        saveTargets(id, v);
        audit.record("SCHEDULE_UPDATED", "scan_schedule", id.toString(),
                Map.of("name", v.name(), "cron", v.cron(), "enabled", v.enabled()));
        return get(id);
    }

    @Transactional
    public void delete(UUID id) {
        ScheduleView s = get(id);
        jdbc.update(AutomationSql.DELETE_SCHEDULE, new MapSqlParameterSource("id", id));
        audit.record("SCHEDULE_DELETED", "scan_schedule", id.toString(), Map.of("name", s.name()));
    }

    private MapSqlParameterSource params(UUID id, Valid v) {
        Instant next = v.enabled() ? CronSchedules.next(v.cron(), v.zone(), clock.instant()).orElse(null) : null;
        return new MapSqlParameterSource().addValue("id", id).addValue("name", v.name()).addValue("cron", v.cron())
                .addValue("timeZone", v.zone().getId()).addValue("scope", v.scope()).addValue("enabled", v.enabled())
                .addValue("nextFireAt", next == null ? null : next.atOffset(java.time.ZoneOffset.UTC), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
    }

    private void saveTargets(UUID id, Valid v) {
        jdbc.update(AutomationSql.DELETE_SCHEDULE_TARGETS, new MapSqlParameterSource("id", id));
        String sql = "NAMESPACES".equals(v.scope()) ? AutomationSql.INSERT_SCHEDULE_NAMESPACE : AutomationSql.INSERT_SCHEDULE_REPOSITORY;
        List<MapSqlParameterSource> batch = new ArrayList<>();
        for (UUID target : v.targets()) {
            batch.add(new MapSqlParameterSource().addValue("id", id).addValue("targetId", target));
        }
        if (!batch.isEmpty()) {
            jdbc.batchUpdate(sql, batch.toArray(MapSqlParameterSource[]::new));
        }
    }

    static ScheduleView view(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new ScheduleView(JdbcRows.uuid(rs, "id"), rs.getString("name"), rs.getString("cron_expression"),
                rs.getString("time_zone"), rs.getString("scope"), rs.getBoolean("enabled"),
                JdbcRows.instant(rs, "next_fire_at"), JdbcRows.instant(rs, "last_fired_at"), JdbcRows.uuid(rs, "last_run_id"),
                rs.getString("last_run_status"), rs.getString("last_outcome"), uuids(JdbcRows.strings(rs, "repository_ids")),
                uuids(JdbcRows.strings(rs, "namespace_ids")), rs.getString("created_by"), JdbcRows.instant(rs, "created_at"),
                JdbcRows.instant(rs, "updated_at"));
    }

    private static List<UUID> uuids(List<String> values) {
        return values.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    private static String currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }
}
