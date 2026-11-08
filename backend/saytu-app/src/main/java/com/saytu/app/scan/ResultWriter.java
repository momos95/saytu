package com.saytu.app.scan;

import com.saytu.app.scan.JobQueue.ClaimedJob;
import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScanStatus;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.finding.FindingDeduplicator;
import com.saytu.core.finding.FindingDeduplicator.Merged;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.scan.JobOutcome;
import com.saytu.scan.ScannerOutcome;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.Types;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Persists a job's outcome in one transaction: scanner executions, deduplicated findings (upsert by
 * fingerprint), occurrences per scanner, automatic resolution, job status, and run completion.
 */
public class ResultWriter {

    /** Counters written on the job. */
    public record Summary(int findings, int newFindings, int resolved) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final JobQueue queue;
    private final ScoreService scores;
    private final WebhookService webhooks;

    public ResultWriter(NamedParameterJdbcTemplate jdbc, JobQueue queue, ScoreService scores, WebhookService webhooks) {
        this.jdbc = jdbc;
        this.queue = queue;
        this.scores = scores;
        this.webhooks = webhooks;
    }

    @Transactional
    public Summary write(ClaimedJob job, JobOutcome outcome) {
        return write(job, outcome, outcome.status());
    }

    /** Records a job that ended without an outcome from the runner (e.g. cancelled, internal error). */
    @Transactional
    public void fail(ClaimedJob job, ScanStatus status, String error) {
        finishJob(job, status, null, error, null, null, new Summary(0, 0, 0), LanguageProfile.empty());
        queue.completeRunIfDone(job.runId());
    }

    @Transactional
    public Summary write(ClaimedJob job, JobOutcome outcome, ScanStatus status) {
        jdbc.update(ScanSql.DELETE_PREVIOUS_EXECUTIONS, new MapSqlParameterSource("jobId", job.id()));

        Map<ScannerId, UUID> executionIds = new EnumMap<>(ScannerId.class);
        List<String> succeeded = new ArrayList<>();
        List<NormalizedFinding> all = new ArrayList<>();
        for (ScannerOutcome s : outcome.scanners()) {
            UUID executionId = jdbc.queryForObject(ScanSql.INSERT_EXECUTION, new MapSqlParameterSource()
                    .addValue("jobId", job.id())
                    .addValue("scannerId", s.scanner().key())
                    .addValue("status", s.status().name())
                    .addValue("toolVersion", s.toolVersion(), Types.VARCHAR)
                    .addValue("rulesetVersion", truncate(s.rulesetVersion(), 255), Types.VARCHAR)
                    .addValue("exitCode", s.exitCode(), Types.INTEGER)
                    .addValue("durationMs", s.duration() == null ? null : s.duration().toMillis(), Types.BIGINT)
                    .addValue("findingsCount", s.findings().size())
                    .addValue("errorMessage", truncate(s.errorMessage(), 2000), Types.VARCHAR)
                    .addValue("startedAt", JdbcRows.timestamp(s.startedAt()), Types.TIMESTAMP_WITH_TIMEZONE)
                    .addValue("finishedAt", JdbcRows.timestamp(s.finishedAt()), Types.TIMESTAMP_WITH_TIMEZONE), UUID.class);
            executionIds.put(s.scanner(), executionId);
            if (s.status() == ScannerExecutionStatus.SUCCEEDED) {
                succeeded.add(s.scanner().key());
            }
            all.addAll(s.findings());
        }

        int created = 0;
        List<Merged> merged = FindingDeduplicator.deduplicate(all);
        for (Merged m : merged) {
            boolean inserted = upsert(job, outcome.commitSha(), m);
            if (inserted) {
                created++;
            }
        }

        int resolved = 0;
        if (outcome.error() == null) {
            resolved = jdbc.update(ScanSql.RESOLVE_MISSING, new MapSqlParameterSource()
                    .addValue("repositoryId", job.repositoryId())
                    .addValue("branch", job.branch())
                    .addValue("jobId", job.id())
                    .addValue("succeeded", succeeded.toArray(String[]::new), Types.ARRAY));
        }
        // occurrences need the execution ids, inserted after the findings
        for (Merged m : merged) {
            UUID findingId = findingId(job, m.fingerprint());
            for (NormalizedFinding source : m.sources()) {
                UUID executionId = executionIds.get(source.scanner());
                if (executionId == null || findingId == null) {
                    continue;
                }
                var location = source.location();
                jdbc.update(ScanSql.INSERT_OCCURRENCE, new MapSqlParameterSource()
                        .addValue("findingId", findingId)
                        .addValue("executionId", executionId)
                        .addValue("jobId", job.id())
                        .addValue("scannerId", source.scanner().key())
                        .addValue("ruleId", truncate(source.ruleId(), 512))
                        .addValue("severity", source.severity().name())
                        .addValue("filePath", location == null ? null : truncate(location.path(), 2048), Types.VARCHAR)
                        .addValue("startLine", location == null ? null : location.startLine(), Types.INTEGER)
                        .addValue("endLine", location == null ? null : location.endLine(), Types.INTEGER));
            }
        }

        Summary summary = new Summary(merged.size(), created, resolved);
        finishJob(job, status, outcome.commitSha(), outcome.error(), outcome.checkoutBytes(),
                (int) Math.min(Integer.MAX_VALUE, outcome.checkoutFiles()), summary, outcome.languages());
        if (outcome.commitSha() != null) {
            jdbc.update(ScanSql.RECORD_BRANCH_SCAN, new MapSqlParameterSource()
                    .addValue("commitSha", outcome.commitSha())
                    .addValue("repositoryId", job.repositoryId())
                    .addValue("branch", job.branch()));
            jdbc.update(ScoreSql.RECORD_LANGUAGES, new MapSqlParameterSource()
                    .addValue("labels", Json.write(outcome.languages().labels().stream().map(Language::key).toList()))
                    .addValue("repositoryId", job.repositoryId()));
        }
        if (outcome.error() == null && status != ScanStatus.CANCELLED) {
            Map<ScannerId, ScannerExecutionStatus> executions = new EnumMap<>(ScannerId.class);
            outcome.scanners().forEach(s -> executions.put(s.scanner(), s.status()));
            scores.recordJob(job.id(), job.repositoryId(), job.branch(), outcome.languages(), executions);
        }
        if (status != ScanStatus.CANCELLED) {
            // after commit, in its own transaction: an alerting problem can never roll back the results
            UUID finishedJob = job.id();
            if (TransactionSynchronizationManager.isSynchronizationActive()) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        webhooks.jobFinished(finishedJob);
                    }
                });
            } else {
                webhooks.jobFinished(finishedJob);
            }
        }
        queue.completeRunIfDone(job.runId());
        return summary;
    }

    private boolean upsert(ClaimedJob job, String commitSha, Merged m) {
        NormalizedFinding f = m.finding();
        var location = f.location();
        var dep = f.dependency();
        MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("repositoryId", job.repositoryId())
                .addValue("branch", job.branch())
                .addValue("fingerprint", m.fingerprint())
                .addValue("type", f.type().name())
                .addValue("severity", f.severity().name())
                .addValue("scannerId", f.scanner().key())
                .addValue("ruleId", truncate(f.ruleId(), 512))
                .addValue("title", truncate(f.title(), 500))
                .addValue("description", f.description())
                .addValue("cwes", f.cwes().stream().filter(c -> c.length() <= 16).toArray(String[]::new), Types.ARRAY)
                .addValue("cve", truncate(f.cve(), 64), Types.VARCHAR)
                .addValue("cvssScore", f.cvssScore() == null ? null
                        : BigDecimal.valueOf(f.cvssScore()).setScale(1, RoundingMode.HALF_UP), Types.NUMERIC)
                .addValue("cvssVector", truncate(f.cvssVector(), 255), Types.VARCHAR)
                .addValue("filePath", location == null ? null : truncate(location.path(), 2048), Types.VARCHAR)
                .addValue("startLine", location == null ? null : location.startLine(), Types.INTEGER)
                .addValue("endLine", location == null ? null : location.endLine(), Types.INTEGER)
                .addValue("ecosystem", dep == null ? null : truncate(dep.ecosystem(), 64), Types.VARCHAR)
                .addValue("packageName", dep == null ? null : truncate(dep.name(), 512), Types.VARCHAR)
                .addValue("packageVersion", dep == null ? null : truncate(dep.installedVersion(), 128), Types.VARCHAR)
                .addValue("fixedVersion", dep == null ? null : truncate(dep.fixedVersion(), 255), Types.VARCHAR)
                .addValue("evidence", f.evidence(), Types.VARCHAR)
                .addValue("recommendation", f.recommendation(), Types.VARCHAR)
                .addValue("references", f.references().toArray(String[]::new), Types.ARRAY)
                .addValue("commitSha", commitSha, Types.VARCHAR)
                .addValue("jobId", job.id());
        List<Boolean> inserted = jdbc.query(ScanSql.UPSERT_FINDING, p, (rs, i) -> rs.getBoolean("inserted"));
        return !inserted.isEmpty() && inserted.getFirst();
    }

    private UUID findingId(ClaimedJob job, String fingerprint) {
        List<UUID> ids = jdbc.query("""
                        SELECT id FROM finding WHERE repository_id = :repositoryId AND branch = :branch AND fingerprint = :fingerprint""",
                new MapSqlParameterSource().addValue("repositoryId", job.repositoryId())
                        .addValue("branch", job.branch()).addValue("fingerprint", fingerprint),
                (rs, i) -> JdbcRows.uuid(rs, "id"));
        return ids.isEmpty() ? null : ids.getFirst();
    }

    private void finishJob(ClaimedJob job, ScanStatus status, String commitSha, String error, Long checkoutBytes,
                           Integer checkoutFiles, Summary summary, LanguageProfile languages) {
        jdbc.update(ScanSql.FINISH_JOB, new MapSqlParameterSource()
                .addValue("jobId", job.id())
                .addValue("status", status.name())
                .addValue("commitSha", commitSha, Types.VARCHAR)
                .addValue("errorMessage", truncate(error, 2000), Types.VARCHAR)
                .addValue("checkoutBytes", checkoutBytes == null || checkoutBytes == 0 ? null : checkoutBytes, Types.BIGINT)
                .addValue("checkoutFiles", checkoutFiles == null || checkoutFiles == 0 ? null : checkoutFiles, Types.INTEGER)
                .addValue("findingsCount", summary.findings())
                .addValue("newFindings", summary.newFindings())
                .addValue("resolvedFindings", summary.resolved())
                .addValue("languages", languagesJson(languages)));
    }

    /** {"java": {"files": 12, "bytes": 34000}, ...} */
    static String languagesJson(LanguageProfile languages) {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        languages.stats().forEach((l, s) -> m.put(l.key(), Map.of("files", s.files(), "bytes", s.bytes())));
        return Json.write(m);
    }

    static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }
}
