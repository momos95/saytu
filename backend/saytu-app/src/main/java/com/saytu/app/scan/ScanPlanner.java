package com.saytu.app.scan;

import com.saytu.app.source.ScanSourceService;
import com.saytu.app.source.ScanSourceService.BranchPlan;
import com.saytu.git.json.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Turns a scan request into jobs (one per repository and branch). Runs in the worker because
 * resolving branches may call the Git platforms; each network call happens outside any transaction.
 */
public class ScanPlanner {

    private static final Logger log = LoggerFactory.getLogger(ScanPlanner.class);
    static final int MANUAL_PRIORITY = 5;
    private static final int MAX_NOTES = 500;

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final ScanSourceService sources;
    private final JobQueue queue;

    public ScanPlanner(NamedParameterJdbcTemplate jdbc, TransactionTemplate tx, ScanSourceService sources, JobQueue queue) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.sources = sources;
        this.queue = queue;
    }

    /** Plans one pending run, if any. @return whether a run was planned */
    public boolean planNext() {
        record Claimed(UUID id, String scope) {
        }
        Claimed run = tx.execute(status -> {
            List<Claimed> rows = jdbc.query(ScanSql.CLAIM_UNPLANNED_RUN, new MapSqlParameterSource(),
                    (rs, i) -> new Claimed(JdbcRows.uuid(rs, "id"), rs.getString("scope")));
            return rows.isEmpty() ? null : rows.getFirst();
        });
        if (run == null) {
            return false;
        }
        try {
            plan(run.id(), run.scope());
        } catch (RuntimeException e) {
            log.error("Planning of scan {} failed", run.id(), e);
            finish(run.id(), List.of(), "planning failed: " + e.getMessage());
        }
        return true;
    }

    void plan(UUID runId, String scopeJson) {
        List<UUID> repositories = repositoriesOf(scopeJson);
        List<Map<String, String>> notes = new ArrayList<>();
        int created = 0;
        for (UUID repositoryId : repositories) {
            if (queue.isCancelRequested(runId)) {
                break;
            }
            BranchPlan branches = sources.branchesToScan(repositoryId);
            if (branches.branches().isEmpty()) {
                note(notes, branches, branches.problem());
                continue;
            }
            for (String branch : branches.branches()) {
                Optional<UUID> job = insertJob(runId, repositoryId, branch);
                if (job.isPresent()) {
                    created++;
                } else {
                    note(notes, branches, "branch " + branch + " already queued or running in another scan");
                }
            }
        }
        finish(runId, notes, created == 0 ? "nothing to scan: no branch could be queued" : null);
    }

    private List<UUID> repositoriesOf(String scopeJson) {
        JsonNode scope = JsonNode.parse(scopeJson == null ? "{}" : scopeJson);
        if (scope.get("allTargets").asBoolean(false)) {
            return sources.allTargetIds();
        }
        List<UUID> requested = scope.get("repositoryIds").textElements().stream().map(UUID::fromString).toList();
        // the selection may have changed since the request
        return List.copyOf(sources.targetsAmong(requested));
    }

    private Optional<UUID> insertJob(UUID runId, UUID repositoryId, String branch) {
        List<UUID> ids = tx.execute(status -> jdbc.query(ScanSql.INSERT_JOB, new MapSqlParameterSource()
                        .addValue("runId", runId).addValue("repositoryId", repositoryId)
                        .addValue("branch", branch).addValue("priority", MANUAL_PRIORITY),
                (rs, i) -> JdbcRows.uuid(rs, "id")));
        return ids == null || ids.isEmpty() ? Optional.empty() : Optional.of(ids.getFirst());
    }

    private static void note(List<Map<String, String>> notes, BranchPlan plan, String text) {
        if (notes.size() >= MAX_NOTES) {
            return;
        }
        Map<String, String> n = new LinkedHashMap<>();
        n.put("repositoryId", plan.repositoryId().toString());
        n.put("repository", plan.fullName() == null ? "" : plan.fullName());
        n.put("note", text == null ? "" : text);
        notes.add(n);
    }

    private void finish(UUID runId, List<Map<String, String>> notes, String error) {
        tx.executeWithoutResult(status -> {
            jdbc.update(ScanSql.FINISH_PLANNING, new MapSqlParameterSource()
                    .addValue("runId", runId)
                    .addValue("notes", toJson(notes))
                    .addValue("errorMessage", error == null ? null : truncate(error), java.sql.Types.VARCHAR));
            queue.completeRunIfDone(runId);
        });
    }

    static String toJson(List<Map<String, String>> notes) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < notes.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('{');
            int j = 0;
            for (var e : notes.get(i).entrySet()) {
                if (j++ > 0) {
                    sb.append(',');
                }
                sb.append(quote(e.getKey())).append(':').append(quote(e.getValue()));
            }
            sb.append('}');
        }
        return sb.append(']').toString();
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    private static String truncate(String s) {
        return s.length() <= 2000 ? s : s.substring(0, 1999) + "…";
    }
}
