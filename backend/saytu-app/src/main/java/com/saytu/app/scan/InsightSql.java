package com.saytu.app.scan;

/**
 * SQL of the phase 6 read models (dashboard, repository detail, reports) and of finding triage.
 * Kept as constants so {@code scripts/verify-scan-sql.sh} runs them on a real PostgreSQL.
 */
final class InsightSql {

    private InsightSql() {
    }

    private static final String SEVERITY_RANK =
            "CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";

    // ------------------------------------------------------------------ triage

    static final String LOCK_FINDING = "SELECT status FROM finding WHERE id = :findingId FOR UPDATE";

    static final String UPDATE_FINDING_STATUS = """
            UPDATE finding SET status = :status, status_reason = :reason, status_changed_by = :user,
                               status_changed_at = now(), version = version + 1
            WHERE id = :findingId""";

    static final String INSERT_STATUS_HISTORY = """
            INSERT INTO finding_status_history (finding_id, from_status, to_status, reason, changed_by)
            VALUES (:findingId, :fromStatus, :toStatus, :reason, :user)""";

    static final String STATUS_HISTORY = """
            SELECT from_status, to_status, reason, changed_by, changed_at
            FROM finding_status_history WHERE finding_id = :findingId ORDER BY changed_at, id""";

    // ------------------------------------------------------------------ dashboard

    static final String DASHBOARD_COUNTERS = """
            SELECT
              (SELECT count(DISTINCT j.repository_id) FROM scan_job j JOIN source_repository r ON r.id = j.repository_id
                WHERE j.status IN ('SUCCEEDED', 'PARTIAL') AND r.removed_at IS NULL) AS audited_repositories,
              (SELECT count(*) FROM finding f JOIN source_repository r ON r.id = f.repository_id
                WHERE f.status = 'OPEN' AND r.removed_at IS NULL) AS open_findings,
              (SELECT count(*) FROM finding f WHERE f.first_seen_at > now() - interval '7 days') AS new_last_7_days,
              (SELECT count(*) FROM finding f WHERE f.resolved_at > now() - interval '7 days') AS resolved_last_7_days,
              (SELECT count(*) FROM finding f WHERE f.status IN ('ACCEPTED_RISK', 'FALSE_POSITIVE')) AS triaged,
              (SELECT max(j.finished_at) FROM scan_job j WHERE j.status IN ('SUCCEEDED', 'PARTIAL')) AS last_audit_at""";

    /** Open findings of repositories still present, per severity and type. */
    static final String OPEN_BY_SEVERITY_TYPE = """
            SELECT f.severity, f.type, count(*) AS n
            FROM finding f JOIN source_repository r ON r.id = f.repository_id
            WHERE f.status = 'OPEN' AND r.removed_at IS NULL
              AND (CAST(:repositoryId AS uuid) IS NULL OR f.repository_id = CAST(:repositoryId AS uuid))
            GROUP BY f.severity, f.type""";

    /** Last snapshot of each day (scope GLOBAL, or one repository). */
    static final String SCORE_TREND = "SELECT DISTINCT ON (date_trunc('day', s.computed_at)) "
            + "date_trunc('day', s.computed_at) AS day, " + ScoreSql.SNAPSHOT_COLUMNS + """

            FROM score_snapshot s
            WHERE s.scope_type = :scopeType
              AND (CAST(:repositoryId AS uuid) IS NULL OR s.repository_id = CAST(:repositoryId AS uuid))
              AND s.computed_at > now() - make_interval(days => :days)
            ORDER BY date_trunc('day', s.computed_at), s.computed_at DESC""";

    /** Findings that appeared / were fixed, per week, over the last 12 weeks. */
    static final String WEEKLY_FLOW = """
            SELECT w.week,
                   (SELECT count(*) FROM finding f WHERE f.first_seen_at >= w.week AND f.first_seen_at < w.week + interval '7 days'
                      AND (CAST(:repositoryId AS uuid) IS NULL OR f.repository_id = CAST(:repositoryId AS uuid))) AS opened,
                   (SELECT count(*) FROM finding f WHERE f.resolved_at >= w.week AND f.resolved_at < w.week + interval '7 days'
                      AND (CAST(:repositoryId AS uuid) IS NULL OR f.repository_id = CAST(:repositoryId AS uuid))) AS resolved
            FROM generate_series(date_trunc('week', now()) - interval '11 weeks', date_trunc('week', now()), interval '1 week') AS w(week)
            ORDER BY w.week""";

    /** Repositories to look at first: open critical findings, then the lowest score, then open high findings. */
    static final String PRIORITY_REPOSITORIES = """
            WITH latest AS (
                SELECT DISTINCT ON (s.repository_id) s.*
                FROM score_snapshot s WHERE s.scope_type = 'REPOSITORY'
                ORDER BY s.repository_id, s.computed_at DESC),
            open AS (
                SELECT f.repository_id,
                       count(*) FILTER (WHERE f.severity = 'CRITICAL') AS critical,
                       count(*) FILTER (WHERE f.severity = 'HIGH') AS high,
                       count(*) FILTER (WHERE f.type IN ('SECURITY', 'SECRET', 'DEPENDENCY')) AS security,
                       count(*) AS total
                FROM finding f WHERE f.status = 'OPEN' GROUP BY f.repository_id)
            SELECT r.id AS repository_id, r.full_name, r.languages::text AS languages,
                   coalesce(o.critical, 0) AS critical, coalesce(o.high, 0) AS high,
                   coalesce(o.security, 0) AS security_findings, coalesce(o.total, 0) AS open_findings,
                   s.security_score, s.quality_score, s.global_score, s.coverage_percent, s.reliability, s.formula_version,
                   s.details::text AS details, s.computed_at
            FROM source_repository r
            LEFT JOIN latest s ON s.repository_id = r.id
            LEFT JOIN open o ON o.repository_id = r.id
            WHERE r.removed_at IS NULL AND (s.repository_id IS NOT NULL OR o.repository_id IS NOT NULL)
            ORDER BY coalesce(o.critical, 0) DESC, s.global_score ASC NULLS LAST, coalesce(o.high, 0) DESC, r.full_name
            LIMIT :limit""";

    // ------------------------------------------------------------------ repository detail

    static final String REPOSITORY_INFO = """
            SELECT r.id, r.full_name, r.name, r.web_url, r.default_branch, r.visibility, r.archived, r.removed_at,
                   r.languages::text AS languages, r.languages_updated_at, r.last_activity_at,
                   n.id AS namespace_id, n.full_path AS namespace, c.name AS connection_name, c.provider_type
            FROM source_repository r
            JOIN git_connection c ON c.id = r.connection_id
            LEFT JOIN git_namespace n ON n.id = r.namespace_id
            WHERE r.id = :repositoryId""";

    static final String OPEN_BY_BRANCH = """
            SELECT f.branch, f.severity, f.type, count(*) AS n
            FROM finding f WHERE f.repository_id = :repositoryId AND f.status = 'OPEN'
            GROUP BY f.branch, f.severity, f.type""";

    static final String TOP_RULES = "SELECT f.scanner_id, f.rule_id, min(f.title) AS title, count(*) AS n, min("
            + SEVERITY_RANK + ") AS severity_rank" + """

            FROM finding f WHERE f.repository_id = :repositoryId AND f.status = 'OPEN'
            GROUP BY f.scanner_id, f.rule_id
            ORDER BY severity_rank, n DESC, f.rule_id
            LIMIT 10""";

    static final String RECENT_JOBS = """
            SELECT j.id, j.scan_run_id, j.branch, j.status, j.commit_sha, j.queued_at, j.started_at, j.finished_at,
                   j.findings_count, j.new_findings, j.resolved_findings, j.error_message
            FROM scan_job j WHERE j.repository_id = :repositoryId
            ORDER BY j.queued_at DESC
            LIMIT 20""";

    // ------------------------------------------------------------------ reports

    static final String REPORT_FINDINGS = "SELECT " + ScanSql.FINDING_COLUMNS + ScanSql.FINDING_DETAIL_COLUMNS
            + ", f.fingerprint\n" + ScanSql.FINDING_FILTER + "\nORDER BY " + SEVERITY_RANK + """
            , s.full_name, f.branch, f.file_path NULLS LAST, f.start_line NULLS LAST, f.id
            LIMIT :limit""";

    /** Latest finished analysis of each repository branch in the scope. */
    static final String REPORT_SCANS = """
            SELECT DISTINCT ON (j.repository_id, j.branch) j.id, r.full_name, j.branch, j.commit_sha, j.finished_at,
                   j.status, j.languages::text AS languages
            FROM scan_job j JOIN source_repository r ON r.id = j.repository_id
            WHERE j.status IN ('SUCCEEDED', 'PARTIAL') AND r.removed_at IS NULL
              AND (CAST(:repositoryId AS uuid) IS NULL OR j.repository_id = CAST(:repositoryId AS uuid))
              AND (CAST(:branch AS varchar) IS NULL OR j.branch = CAST(:branch AS varchar))
            ORDER BY j.repository_id, j.branch, j.finished_at DESC""";

    static final String REPORT_EXECUTIONS = """
            SELECT e.scan_job_id, e.scanner_id, e.status, e.tool_version, e.ruleset_version, e.findings_count, e.error_message
            FROM scanner_execution e WHERE e.scan_job_id = ANY(CAST(:jobIds AS uuid[]))
            ORDER BY e.scan_job_id, e.scanner_id""";

    static final String INSERT_REPORT = """
            INSERT INTO report (format, status, sha256, size_bytes, filters, created_by)
            VALUES (:format, 'READY', :sha256, :size, CAST(:filters AS jsonb), :user)""";
}
