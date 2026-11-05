package com.saytu.app.scan;

import com.saytu.app.audit.AuditService;
import com.saytu.app.scan.ScanViews.PageView;
import com.saytu.app.scan.ScanViews.PlanningNote;
import com.saytu.app.scan.ScanViews.ScanCreated;
import com.saytu.app.scan.ScanViews.ScanJobView;
import com.saytu.app.scan.ScanViews.ScanRequest;
import com.saytu.app.scan.ScanViews.ScanRunDetail;
import com.saytu.app.scan.ScanViews.ScanRunView;
import com.saytu.app.scan.ScanViews.ScannerExecutionView;
import com.saytu.app.source.ScanSourceService;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.git.json.JsonNode;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Scan requests and history (API side). Creating a scan only records the request: the worker plans
 * and executes it, so the API never clones nor calls the Git platforms for a scan.
 */
@Service
public class ScanService {

    static final int MAX_PAGE_SIZE = 100;

    private final NamedParameterJdbcTemplate jdbc;
    private final ScanSourceService sources;
    private final AuditService audit;

    public ScanService(NamedParameterJdbcTemplate jdbc, ScanSourceService sources, AuditService audit) {
        this.jdbc = jdbc;
        this.sources = sources;
        this.audit = audit;
    }

    @Transactional
    public ScanCreated request(ScanRequest request) {
        String scope;
        if (request.allTargets()) {
            if (!request.repositoryIds().isEmpty()) {
                throw new IllegalArgumentException("Choose either allTargets or a list of repositories, not both");
            }
            if (sources.allTargetIds().isEmpty()) {
                throw new IllegalArgumentException("No repository is selected for audit");
            }
            scope = "{\"allTargets\":true}";
        } else {
            Set<UUID> ids = new LinkedHashSet<>(request.repositoryIds());
            if (ids.isEmpty()) {
                throw new IllegalArgumentException("Give at least one repository, or allTargets=true");
            }
            Set<UUID> targets = sources.targetsAmong(List.copyOf(ids));
            if (targets.size() != ids.size()) {
                throw new IllegalArgumentException((ids.size() - targets.size())
                        + " repository(ies) are not selected for audit (or archived / removed)");
            }
            scope = ids.stream().map(id -> "\"" + id + "\"").collect(Collectors.joining(",", "{\"repositoryIds\":[", "]}"));
        }
        String user = currentUser();
        UUID id = jdbc.queryForObject(ScanSql.INSERT_RUN, new MapSqlParameterSource()
                .addValue("triggerType", "MANUAL")
                .addValue("requestedBy", user)
                .addValue("scope", scope), UUID.class);
        audit.record("SCAN_REQUESTED", "scan_run", String.valueOf(id),
                Map.of("allTargets", request.allTargets(), "repositories", request.repositoryIds().size()));
        return new ScanCreated(id);
    }

    @Transactional(readOnly = true)
    public PageView<ScanRunView> list(int page, int size) {
        int safeSize = Math.clamp(size, 1, MAX_PAGE_SIZE);
        int safePage = Math.max(page, 0);
        long total = jdbc.getJdbcTemplate().queryForObject(ScanSql.COUNT_RUNS, Long.class);
        List<ScanRunView> items = jdbc.query(ScanSql.LIST_RUNS, new MapSqlParameterSource()
                .addValue("limit", safeSize).addValue("offset", (long) safePage * safeSize), RUN_MAPPER);
        return new PageView<>(items, safePage, safeSize, total, (int) ((total + safeSize - 1) / safeSize));
    }

    @Transactional(readOnly = true)
    public ScanRunDetail get(UUID runId) {
        MapSqlParameterSource p = new MapSqlParameterSource("runId", runId);
        List<ScanRunView> runs = jdbc.query(ScanSql.GET_RUN, p, RUN_MAPPER);
        if (runs.isEmpty()) {
            throw new ResourceNotFoundException("Scan " + runId + " not found");
        }
        Map<UUID, List<ScannerExecutionView>> executions = new HashMap<>();
        jdbc.query(ScanSql.RUN_EXECUTIONS, p, rs -> {
            executions.computeIfAbsent(JdbcRows.uuid(rs, "scan_job_id"), k -> new ArrayList<>()).add(
                    new ScannerExecutionView(rs.getString("scanner_id"), rs.getString("status"),
                            rs.getString("tool_version"), rs.getString("ruleset_version"),
                            JdbcRows.longOrNull(rs, "duration_ms"), rs.getInt("findings_count"),
                            rs.getString("error_message")));
        });
        List<ScanJobView> jobs = jdbc.query(ScanSql.RUN_JOBS, p, (rs, i) -> {
            UUID jobId = JdbcRows.uuid(rs, "id");
            return new ScanJobView(jobId, JdbcRows.uuid(rs, "repository_id"), rs.getString("full_name"),
                    rs.getString("branch"), rs.getString("commit_sha"), rs.getString("status"), rs.getInt("attempt"),
                    JdbcRows.instant(rs, "queued_at"), JdbcRows.instant(rs, "started_at"),
                    JdbcRows.instant(rs, "finished_at"), rs.getString("error_message"),
                    JdbcRows.longOrNull(rs, "checkout_bytes"), rs.getInt("findings_count"), rs.getInt("new_findings"),
                    rs.getInt("resolved_findings"), executions.getOrDefault(jobId, List.of()));
        });
        String notesJson = jdbc.queryForObject("SELECT planning_notes::text FROM scan_run WHERE id = :runId", p, String.class);
        return new ScanRunDetail(runs.getFirst(), jobs, parseNotes(notesJson));
    }

    /** Stops a scan: queued jobs are cancelled now, running jobs stop before their next scanner. */
    @Transactional
    public ScanRunDetail cancel(UUID runId) {
        MapSqlParameterSource p = new MapSqlParameterSource("runId", runId);
        int updated = jdbc.update(ScanSql.REQUEST_CANCEL, p);
        if (updated == 0) {
            get(runId); // 404 when it does not exist
            throw new IllegalArgumentException("This scan is already finished");
        }
        jdbc.update(ScanSql.CANCEL_UNPLANNED_RUN, p);
        jdbc.update(ScanSql.CANCEL_QUEUED_JOBS, p);
        jdbc.update(ScanSql.COMPLETE_RUN, p);
        audit.record("SCAN_CANCELLED", "scan_run", runId.toString(), Map.of());
        return get(runId);
    }

    static List<PlanningNote> parseNotes(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        List<PlanningNote> notes = new ArrayList<>();
        for (JsonNode n : JsonNode.parse(json).elements()) {
            String id = n.get("repositoryId").asText();
            notes.add(new PlanningNote(id == null ? null : UUID.fromString(id), n.get("repository").asText(),
                    n.get("note").asText()));
        }
        return notes;
    }

    private static String currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }

    static final RowMapper<ScanRunView> RUN_MAPPER = (rs, i) -> new ScanRunView(
            JdbcRows.uuid(rs, "id"), rs.getString("trigger_type"), rs.getString("requested_by"), rs.getString("status"),
            rs.getInt("total_jobs"), rs.getLong("finished_jobs"), rs.getLong("problem_jobs"), rs.getLong("new_findings"),
            JdbcRows.instant(rs, "created_at"), JdbcRows.instant(rs, "started_at"), JdbcRows.instant(rs, "finished_at"),
            rs.getObject("planned_at") != null, rs.getBoolean("cancel_requested"), rs.getString("error_message"),
            scopeLabel(rs.getString("scope")));

    /** "all" or the number of repositories requested. */
    static String scopeLabel(String scopeJson) {
        if (scopeJson == null) {
            return null;
        }
        JsonNode scope = JsonNode.parse(scopeJson);
        if (scope.get("allTargets").asBoolean(false)) {
            return "ALL_TARGETS";
        }
        return scope.get("repositoryIds").size() + " REPOSITORIES";
    }
}
