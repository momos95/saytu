package com.saytu.app.scan;

/**
 * SQL of the scan engine, in one place so that every statement can be checked against PostgreSQL
 * (scripts/verify-scan-sql.sh runs them on a throw-away database built from the Flyway migrations).
 * <p>
 * Plain JDBC is used rather than JPA: the queue relies on {@code FOR UPDATE SKIP LOCKED}, findings on
 * {@code INSERT ... ON CONFLICT}, and results are written in bulk.
 */
final class ScanSql {

    private ScanSql() {
    }

    // ------------------------------------------------------------------ runs (API)

    static final String INSERT_RUN = """
            INSERT INTO scan_run (trigger_type, requested_by, status, scope)
            VALUES (:triggerType, :requestedBy, 'QUEUED', CAST(:scope AS jsonb))
            RETURNING id""";

    static final String RUN_COLUMNS = """
            r.id, r.trigger_type, r.requested_by, r.status, r.total_jobs, r.created_at, r.started_at, r.finished_at,
            r.planned_at, r.cancel_requested, r.error_message, r.scope::text AS scope, r.planning_notes::text AS planning_notes,
            (SELECT count(*) FROM scan_job j WHERE j.scan_run_id = r.id AND j.status NOT IN ('QUEUED', 'RUNNING')) AS finished_jobs,
            (SELECT count(*) FROM scan_job j WHERE j.scan_run_id = r.id AND j.status IN ('FAILED', 'PARTIAL')) AS problem_jobs,
            (SELECT coalesce(sum(j.new_findings), 0) FROM scan_job j WHERE j.scan_run_id = r.id) AS new_findings""";

    static final String LIST_RUNS = "SELECT " + RUN_COLUMNS + """

            FROM scan_run r
            ORDER BY r.created_at DESC
            LIMIT :limit OFFSET :offset""";

    static final String COUNT_RUNS = "SELECT count(*) FROM scan_run";

    static final String GET_RUN = "SELECT " + RUN_COLUMNS + " FROM scan_run r WHERE r.id = :runId";

    static final String RUN_JOBS = """
            SELECT j.id, j.repository_id, s.full_name, j.branch, j.commit_sha, j.status, j.attempt, j.queued_at,
                   j.started_at, j.finished_at, j.error_message, j.checkout_bytes, j.findings_count, j.new_findings,
                   j.resolved_findings
            FROM scan_job j JOIN source_repository s ON s.id = j.repository_id
            WHERE j.scan_run_id = :runId
            ORDER BY s.full_name, j.branch""";

    static final String RUN_EXECUTIONS = """
            SELECT e.scan_job_id, e.scanner_id, e.status, e.tool_version, e.ruleset_version, e.duration_ms,
                   e.findings_count, e.error_message
            FROM scanner_execution e JOIN scan_job j ON j.id = e.scan_job_id
            WHERE j.scan_run_id = :runId
            ORDER BY e.scanner_id""";

    static final String REQUEST_CANCEL = """
            UPDATE scan_run SET cancel_requested = TRUE
            WHERE id = :runId AND status IN ('QUEUED', 'RUNNING')""";

    static final String CANCEL_QUEUED_JOBS = """
            UPDATE scan_job SET status = 'CANCELLED', finished_at = now(), error_message = 'cancelled before start'
            WHERE scan_run_id = :runId AND status = 'QUEUED'""";

    static final String CANCEL_UNPLANNED_RUN = """
            UPDATE scan_run SET status = 'CANCELLED', finished_at = now(), planned_at = coalesce(planned_at, now())
            WHERE id = :runId AND planned_at IS NULL AND status = 'QUEUED'""";

    /** Closes a run whose jobs are all finished. Zero job means planning produced nothing: FAILED. */
    static final String COMPLETE_RUN = """
            UPDATE scan_run r SET status = agg.status, finished_at = now()
            FROM (SELECT CASE
                         WHEN count(*) FILTER (WHERE status IN ('QUEUED', 'RUNNING')) > 0 THEN NULL
                         WHEN count(*) = 0 THEN 'FAILED'
                         WHEN count(*) FILTER (WHERE status = 'SUCCEEDED') = count(*) THEN 'SUCCEEDED'
                         WHEN count(*) FILTER (WHERE status IN ('SUCCEEDED', 'PARTIAL')) > 0 THEN 'PARTIAL'
                         WHEN count(*) FILTER (WHERE status = 'CANCELLED') > 0 THEN 'CANCELLED'
                         ELSE 'FAILED' END AS status
                  FROM scan_job WHERE scan_run_id = :runId) agg
            WHERE r.id = :runId AND r.planned_at IS NOT NULL AND r.status IN ('QUEUED', 'RUNNING')
              AND agg.status IS NOT NULL""";

    // ------------------------------------------------------------------ planning (worker)

    static final String CLAIM_UNPLANNED_RUN = """
            UPDATE scan_run SET planned_at = now(), status = 'RUNNING', started_at = coalesce(started_at, now())
            WHERE id = (SELECT id FROM scan_run
                        WHERE planned_at IS NULL AND status = 'QUEUED' AND NOT cancel_requested
                        ORDER BY created_at
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1)
            RETURNING id, scope::text AS scope""";

    /** One active job per (repository, branch): a branch already queued by another run is not queued twice. */
    static final String INSERT_JOB = """
            INSERT INTO scan_job (scan_run_id, repository_id, branch, priority)
            VALUES (:runId, :repositoryId, :branch, :priority)
            ON CONFLICT (repository_id, branch) WHERE status IN ('QUEUED', 'RUNNING') DO NOTHING
            RETURNING id""";

    static final String FINISH_PLANNING = """
            UPDATE scan_run SET total_jobs = (SELECT count(*) FROM scan_job WHERE scan_run_id = :runId),
                                planning_notes = CAST(:notes AS jsonb),
                                error_message = :errorMessage
            WHERE id = :runId""";

    // ------------------------------------------------------------------ queue (worker)

    static final String CLAIM_JOB = """
            UPDATE scan_job j
            SET status = 'RUNNING', locked_by = :workerId, lease_expires_at = now() + make_interval(secs => :leaseSeconds),
                started_at = now(), attempt = j.attempt + 1, error_message = NULL
            WHERE j.id = (SELECT q.id FROM scan_job q JOIN scan_run r ON r.id = q.scan_run_id
                          WHERE q.status = 'QUEUED' AND NOT r.cancel_requested
                          ORDER BY q.priority, q.queued_at
                          FOR UPDATE OF q SKIP LOCKED
                          LIMIT 1)
            RETURNING j.id, j.scan_run_id, j.repository_id, j.branch, j.attempt""";

    static final String MARK_RUN_RUNNING = """
            UPDATE scan_run SET status = 'RUNNING', started_at = coalesce(started_at, now())
            WHERE id = :runId AND status = 'QUEUED'""";

    static final String RENEW_LEASE = """
            UPDATE scan_job SET lease_expires_at = now() + make_interval(secs => :leaseSeconds)
            WHERE id = :jobId AND locked_by = :workerId AND status = 'RUNNING'""";

    static final String CANCEL_REQUESTED = "SELECT cancel_requested FROM scan_run WHERE id = :runId";

    /** Jobs of a crashed worker (lease expired) go back to the queue, up to max_attempts. */
    static final String REQUEUE_EXPIRED = """
            UPDATE scan_job
            SET status = CASE WHEN attempt < max_attempts THEN 'QUEUED' ELSE 'FAILED' END,
                error_message = CASE WHEN attempt < max_attempts THEN 'worker lost (lease expired): retried'
                                     ELSE 'worker lost (lease expired) after ' || attempt || ' attempts' END,
                queued_at = CASE WHEN attempt < max_attempts THEN now() ELSE queued_at END,
                finished_at = CASE WHEN attempt < max_attempts THEN NULL ELSE now() END,
                locked_by = NULL, lease_expires_at = NULL
            WHERE status = 'RUNNING' AND (lease_expires_at < now() OR locked_by = :workerId)
            RETURNING scan_run_id""";

    // ------------------------------------------------------------------ results (worker)

    static final String DELETE_PREVIOUS_EXECUTIONS = "DELETE FROM scanner_execution WHERE scan_job_id = :jobId";

    static final String INSERT_EXECUTION = """
            INSERT INTO scanner_execution (scan_job_id, scanner_id, status, tool_version, ruleset_version, exit_code,
                                           duration_ms, findings_count, error_message, started_at, finished_at)
            VALUES (:jobId, :scannerId, :status, :toolVersion, :rulesetVersion, :exitCode, :durationMs, :findingsCount,
                    :errorMessage, :startedAt, :finishedAt)
            RETURNING id""";

    static final String UPSERT_FINDING = """
            INSERT INTO finding (repository_id, branch, fingerprint, type, severity, scanner_id, rule_id, title, description,
                                 cwe_ids, cve_id, cvss_score, cvss_vector, file_path, start_line, end_line,
                                 package_ecosystem, package_name, package_version, fixed_version, evidence_redacted,
                                 recommendation, references_urls, commit_sha, first_seen_job_id, last_seen_job_id)
            VALUES (:repositoryId, :branch, :fingerprint, :type, :severity, :scannerId, :ruleId, :title, :description,
                    CAST(:cwes AS varchar(16)[]), :cve, :cvssScore, :cvssVector, :filePath, :startLine, :endLine,
                    :ecosystem, :packageName, :packageVersion, :fixedVersion, :evidence,
                    :recommendation, CAST(:references AS text[]), :commitSha, :jobId, :jobId)
            ON CONFLICT (repository_id, branch, fingerprint) DO UPDATE SET
                type = EXCLUDED.type, severity = EXCLUDED.severity, scanner_id = EXCLUDED.scanner_id,
                rule_id = EXCLUDED.rule_id, title = EXCLUDED.title, description = EXCLUDED.description,
                cwe_ids = EXCLUDED.cwe_ids, cve_id = EXCLUDED.cve_id, cvss_score = EXCLUDED.cvss_score,
                cvss_vector = EXCLUDED.cvss_vector, file_path = EXCLUDED.file_path, start_line = EXCLUDED.start_line,
                end_line = EXCLUDED.end_line, package_ecosystem = EXCLUDED.package_ecosystem,
                package_name = EXCLUDED.package_name, package_version = EXCLUDED.package_version,
                fixed_version = EXCLUDED.fixed_version, evidence_redacted = EXCLUDED.evidence_redacted,
                recommendation = EXCLUDED.recommendation, references_urls = EXCLUDED.references_urls,
                commit_sha = EXCLUDED.commit_sha, last_seen_job_id = EXCLUDED.last_seen_job_id, last_seen_at = now(),
                status = CASE WHEN finding.status = 'RESOLVED' THEN 'OPEN' ELSE finding.status END,
                resolved_at = CASE WHEN finding.status = 'RESOLVED' THEN NULL ELSE finding.resolved_at END,
                version = finding.version + 1
            RETURNING id, (xmax = 0) AS inserted""";

    static final String INSERT_OCCURRENCE = """
            INSERT INTO finding_occurrence (finding_id, scanner_execution_id, scan_job_id, scanner_id, rule_id,
                                            reported_severity, file_path, start_line, end_line)
            VALUES (:findingId, :executionId, :jobId, :scannerId, :ruleId, :severity, :filePath, :startLine, :endLine)
            ON CONFLICT DO NOTHING""";

    /**
     * OPEN findings not reported by this job become RESOLVED, but only when every scanner that ever
     * reported them ran successfully in this job: a failed, timed-out or disabled scanner never "fixes"
     * anything. Human decisions (ACCEPTED_RISK, FALSE_POSITIVE) are left untouched.
     */
    static final String RESOLVE_MISSING = """
            WITH resolved AS (
                UPDATE finding f
                SET status = 'RESOLVED', resolved_at = now(), status_changed_at = now(), status_changed_by = 'system',
                    version = f.version + 1
                WHERE f.repository_id = :repositoryId AND f.branch = :branch AND f.status = 'OPEN'
                  AND f.last_seen_job_id IS DISTINCT FROM :jobId
                  AND f.scanner_id = ANY(CAST(:succeeded AS varchar[]))
                  AND NOT EXISTS (SELECT 1 FROM finding_occurrence o
                                  WHERE o.finding_id = f.id AND NOT (o.scanner_id = ANY(CAST(:succeeded AS varchar[]))))
                RETURNING f.id)
            INSERT INTO finding_status_history (finding_id, from_status, to_status, reason, changed_by)
            SELECT id, 'OPEN', 'RESOLVED', 'not reported by scan job ' || CAST(:jobId AS text), 'system' FROM resolved""";

    static final String FINISH_JOB = """
            UPDATE scan_job
            SET status = :status, commit_sha = :commitSha, error_message = :errorMessage, finished_at = now(),
                locked_by = NULL, lease_expires_at = NULL, checkout_bytes = :checkoutBytes, checkout_files = :checkoutFiles,
                findings_count = :findingsCount, new_findings = :newFindings, resolved_findings = :resolvedFindings
            WHERE id = :jobId""";

    static final String RECORD_BRANCH_SCAN = """
            UPDATE repository_branch SET last_scanned_commit = :commitSha, last_scanned_at = now()
            WHERE repository_id = :repositoryId AND name = :branch""";

    // ------------------------------------------------------------------ findings (API)

    static final String FINDING_COLUMNS = """
            f.id, f.repository_id, s.full_name AS repository_name, f.branch, f.type, f.severity, f.scanner_id, f.rule_id,
            f.title, f.file_path, f.start_line, f.end_line, f.cwe_ids, f.cve_id, f.cvss_score, f.package_name,
            f.package_version, f.fixed_version, f.status, f.first_seen_at, f.last_seen_at, f.commit_sha,
            ARRAY(SELECT DISTINCT o.scanner_id FROM finding_occurrence o WHERE o.finding_id = f.id ORDER BY 1) AS scanners""";

    static final String FINDING_DETAIL_COLUMNS = """
            , f.description, f.evidence_redacted, f.recommendation, f.references_urls, f.cvss_vector, f.package_ecosystem,
            f.resolved_at, f.status_reason, f.status_changed_by, f.status_changed_at""";

    static final String GET_FINDING = "SELECT " + FINDING_COLUMNS + FINDING_DETAIL_COLUMNS + """

            FROM finding f JOIN source_repository s ON s.id = f.repository_id
            WHERE f.id = :findingId""";

    /** Filters are optional: a NULL parameter disables its condition. */
    static final String FINDING_FILTER = """
            FROM finding f JOIN source_repository s ON s.id = f.repository_id
            WHERE (CAST(:repositoryId AS uuid) IS NULL OR f.repository_id = CAST(:repositoryId AS uuid))
              AND (CAST(:branch AS varchar) IS NULL OR f.branch = CAST(:branch AS varchar))
              AND (CAST(:severities AS varchar[]) IS NULL OR f.severity = ANY(CAST(:severities AS varchar[])))
              AND (CAST(:types AS varchar[]) IS NULL OR f.type = ANY(CAST(:types AS varchar[])))
              AND (CAST(:statuses AS varchar[]) IS NULL OR f.status = ANY(CAST(:statuses AS varchar[])))
              AND (CAST(:scanner AS varchar) IS NULL OR EXISTS (SELECT 1 FROM finding_occurrence o
                     WHERE o.finding_id = f.id AND o.scanner_id = CAST(:scanner AS varchar)))
              AND (CAST(:text AS varchar) IS NULL
                   OR f.title ILIKE CAST(:text AS varchar) ESCAPE '\\'
                   OR f.rule_id ILIKE CAST(:text AS varchar) ESCAPE '\\'
                   OR coalesce(f.file_path, '') ILIKE CAST(:text AS varchar) ESCAPE '\\'
                   OR coalesce(f.cve_id, '') ILIKE CAST(:text AS varchar) ESCAPE '\\'
                   OR coalesce(f.package_name, '') ILIKE CAST(:text AS varchar) ESCAPE '\\')""";

    static final String LIST_FINDINGS = "SELECT " + FINDING_COLUMNS + "\n" + FINDING_FILTER + """

            ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                     f.last_seen_at DESC, f.id
            LIMIT :limit OFFSET :offset""";

    static final String COUNT_FINDINGS = "SELECT count(*) " + FINDING_FILTER;

    static final String FINDING_COUNTS_BY_SEVERITY = "SELECT f.severity, count(*) " + FINDING_FILTER + " GROUP BY f.severity";

    static final String FINDING_OCCURRENCES = """
            SELECT o.scanner_id, o.rule_id, o.reported_severity, o.file_path, o.start_line, o.detected_at, o.scan_job_id
            FROM finding_occurrence o WHERE o.finding_id = :findingId
            ORDER BY o.detected_at DESC
            LIMIT 50""";
}
