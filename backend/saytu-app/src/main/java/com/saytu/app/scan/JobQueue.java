package com.saytu.app.scan;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * The job queue is the {@code scan_job} table (ADR-0002): claims use {@code FOR UPDATE SKIP LOCKED},
 * so several workers can share it without a broker, and a lease protects against crashed workers.
 */
@Component
public class JobQueue {

    /** A job handed to a worker. */
    public record ClaimedJob(UUID id, UUID runId, UUID repositoryId, String branch, int attempt) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public JobQueue(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public Optional<ClaimedJob> claim(String workerId, Duration lease) {
        List<ClaimedJob> claimed = jdbc.query(ScanSql.CLAIM_JOB, new MapSqlParameterSource()
                        .addValue("workerId", workerId)
                        .addValue("leaseSeconds", lease.toSeconds()),
                (rs, i) -> new ClaimedJob(JdbcRows.uuid(rs, "id"), JdbcRows.uuid(rs, "scan_run_id"),
                        JdbcRows.uuid(rs, "repository_id"), rs.getString("branch"), rs.getInt("attempt")));
        if (claimed.isEmpty()) {
            return Optional.empty();
        }
        jdbc.update(ScanSql.MARK_RUN_RUNNING, new MapSqlParameterSource("runId", claimed.getFirst().runId()));
        return Optional.of(claimed.getFirst());
    }

    /** @return {@code false} when the lease was lost (job re-queued by another worker) */
    @Transactional
    public boolean renewLease(UUID jobId, String workerId, Duration lease) {
        return jdbc.update(ScanSql.RENEW_LEASE, new MapSqlParameterSource()
                .addValue("jobId", jobId).addValue("workerId", workerId)
                .addValue("leaseSeconds", lease.toSeconds())) == 1;
    }

    @Transactional(readOnly = true)
    public boolean isCancelRequested(UUID runId) {
        Boolean b = jdbc.queryForObject(ScanSql.CANCEL_REQUESTED, new MapSqlParameterSource("runId", runId), Boolean.class);
        return Boolean.TRUE.equals(b);
    }

    /**
     * Re-queues jobs whose lease expired, and those still marked as held by {@code workerId} (this
     * worker restarted while running them), then closes the runs that became complete.
     */
    @Transactional
    public int requeueAbandoned(String workerId) {
        List<UUID> runs = jdbc.query(ScanSql.REQUEUE_EXPIRED, new MapSqlParameterSource("workerId", workerId),
                (rs, i) -> JdbcRows.uuid(rs, "scan_run_id"));
        Set<UUID> distinct = new LinkedHashSet<>(runs);
        for (UUID run : distinct) {
            completeRunIfDone(run);
        }
        return runs.size();
    }

    @Transactional
    public void completeRunIfDone(UUID runId) {
        jdbc.update(ScanSql.COMPLETE_RUN, new MapSqlParameterSource("runId", runId));
    }
}
