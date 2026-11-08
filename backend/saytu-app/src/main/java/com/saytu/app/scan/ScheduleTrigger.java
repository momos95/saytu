package com.saytu.app.scan;

import com.saytu.app.audit.AuditService;
import com.saytu.app.source.ScanSourceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Types;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Fires due schedules (worker only): each firing records an ordinary audit request (trigger SCHEDULED)
 * that the planner turns into jobs. A firing is skipped, with its reason, when the previous audit of
 * the same schedule is still queued or running, or when nothing is selected.
 */
@Component
@ConditionalOnProperty(prefix = "saytu.scan.worker", name = "enabled", havingValue = "true")
public class ScheduleTrigger {

    private static final Logger log = LoggerFactory.getLogger(ScheduleTrigger.class);

    private final NamedParameterJdbcTemplate jdbc;
    private final ScanSourceService sources;
    private final AuditService audit;
    private final Clock clock;

    public ScheduleTrigger(NamedParameterJdbcTemplate jdbc, ScanSourceService sources, AuditService audit, Clock clock) {
        this.jdbc = jdbc;
        this.sources = sources;
        this.audit = audit;
        this.clock = clock;
    }

    @Scheduled(fixedDelayString = "${saytu.scan.schedule-poll-interval:PT30S}", initialDelayString = "PT20S")
    @Transactional
    public void fireDueSchedules() {
        List<ScheduleService.ScheduleView> due = jdbc.query(AutomationSql.CLAIM_DUE_SCHEDULES, new MapSqlParameterSource(),
                (rs, i) -> ScheduleService.view(rs));
        for (ScheduleService.ScheduleView s : due) {
            try {
                fire(s);
            } catch (RuntimeException e) {
                log.warn("Schedule '{}' could not fire: {}", s.name(), e.getMessage());
                record(s, null, "échec : " + e.getMessage());
            }
        }
    }

    private void fire(ScheduleService.ScheduleView s) {
        MapSqlParameterSource id = new MapSqlParameterSource("id", s.id());
        if (Boolean.TRUE.equals(jdbc.queryForObject(AutomationSql.SCHEDULE_HAS_ACTIVE_RUN, id, Boolean.class))) {
            record(s, null, "ignoré : l'audit précédent de cette planification n'est pas terminé");
            return;
        }
        String scope;
        switch (s.scope()) {
            case "ALL_SELECTED" -> {
                if (sources.allTargetIds().isEmpty()) {
                    record(s, null, "ignoré : aucun dépôt sélectionné pour l'audit");
                    return;
                }
                scope = "{\"allTargets\":true}";
            }
            case "NAMESPACES" -> {
                List<UUID> inNamespaces = jdbc.queryForList(AutomationSql.TARGETS_IN_NAMESPACES, new MapSqlParameterSource()
                        .addValue("namespaceIds", s.namespaceIds().toArray(UUID[]::new), Types.ARRAY), UUID.class);
                scope = repositoryScope(sources.targetsAmong(inNamespaces));
            }
            default -> scope = repositoryScope(sources.targetsAmong(s.repositoryIds()));
        }
        if (scope == null) {
            record(s, null, "ignoré : aucun des dépôts visés n'est sélectionné pour l'audit");
            return;
        }
        UUID runId = jdbc.queryForObject(AutomationSql.INSERT_SCHEDULED_RUN, id.addValue("requestedBy", "planification : " + s.name())
                .addValue("scope", scope), UUID.class);
        record(s, runId, "audit lancé");
        audit.record("SCAN_SCHEDULED", "scan_run", String.valueOf(runId), Map.of("schedule", s.name()));
        log.info("Schedule '{}' fired: audit {}", s.name(), runId);
    }

    static String repositoryScope(Set<UUID> ids) {
        if (ids.isEmpty()) {
            return null;
        }
        return ids.stream().sorted().map(id -> "\"" + id + "\"").collect(Collectors.joining(",", "{\"repositoryIds\":[", "]}"));
    }

    private void record(ScheduleService.ScheduleView s, UUID runId, String outcome) {
        Instant next = CronSchedules.next(s.cronExpression(), CronSchedules.zone(s.timeZone()), clock.instant()).orElse(null);
        jdbc.update(AutomationSql.RECORD_FIRING, new MapSqlParameterSource().addValue("id", s.id())
                .addValue("nextFireAt", next == null ? null : next.atOffset(ZoneOffset.UTC), Types.TIMESTAMP_WITH_TIMEZONE)
                .addValue("outcome", outcome.length() > 500 ? outcome.substring(0, 500) : outcome)
                .addValue("runId", runId, Types.OTHER));
    }
}
