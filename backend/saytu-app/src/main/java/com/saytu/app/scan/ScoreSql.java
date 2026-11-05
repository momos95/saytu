package com.saytu.app.scan;

/** SQL of the scores (checked by scripts/verify-scan-sql.sh like {@link ScanSql}). */
final class ScoreSql {

    private ScoreSql() {
    }

    static final String FORMULA = "SELECT value::text FROM app_setting WHERE key = 'scoring.formula'";

    static final String UPDATE_FORMULA = """
            UPDATE app_setting SET value = CAST(:value AS jsonb), updated_by = :updatedBy, updated_at = now()
            WHERE key = 'scoring.formula'""";

    /** OPEN findings of a branch per type and severity (triaged and resolved ones excluded). */
    static final String OPEN_COUNTS = """
            SELECT type, severity, count(*) AS n FROM finding
            WHERE repository_id = :repositoryId AND branch = :branch AND status = 'OPEN'
            GROUP BY type, severity""";

    static final String INSERT_SNAPSHOT = """
            INSERT INTO score_snapshot (scope_type, namespace_id, repository_id, branch, scan_job_id, security_score,
                                        quality_score, global_score, coverage_percent, reliability, formula_version, details)
            VALUES (:scopeType, :namespaceId, :repositoryId, :branch, :scanJobId, :security, :quality, :global, :coverage,
                    :reliability, :formulaVersion, CAST(:details AS jsonb))""";

    static final String SNAPSHOT_COLUMNS = """
            s.security_score, s.quality_score, s.global_score, s.coverage_percent, s.reliability, s.formula_version,
            s.details::text AS details, s.computed_at""";

    /** Latest branch snapshots of a repository, for branches analysed in the last 90 days. */
    static final String LATEST_BRANCH_SNAPSHOTS = "SELECT DISTINCT ON (s.branch) s.branch, " + SNAPSHOT_COLUMNS + """

            FROM score_snapshot s
            WHERE s.scope_type = 'BRANCH' AND s.repository_id = :repositoryId AND s.computed_at > now() - interval '90 days'
            ORDER BY s.branch, s.computed_at DESC""";

    /** Latest repository snapshot of each repository (not removed), with its organisation. */
    static final String LATEST_REPOSITORY_SNAPSHOTS = "SELECT DISTINCT ON (r.id) r.id AS repository_id, r.namespace_id, "
            + "r.full_name, " + SNAPSHOT_COLUMNS + """

            FROM source_repository r
            JOIN score_snapshot s ON s.scope_type = 'REPOSITORY' AND s.repository_id = r.id
            WHERE r.removed_at IS NULL AND (CAST(:namespaceId AS uuid) IS NULL OR r.namespace_id = CAST(:namespaceId AS uuid))
            ORDER BY r.id, s.computed_at DESC""";

    static final String LATEST_NAMESPACE_SNAPSHOTS = "SELECT DISTINCT ON (n.id) n.id AS namespace_id, n.full_path, "
            + SNAPSHOT_COLUMNS + """

            FROM git_namespace n
            JOIN score_snapshot s ON s.scope_type = 'NAMESPACE' AND s.namespace_id = n.id
            WHERE n.removed_at IS NULL
            ORDER BY n.id, s.computed_at DESC""";

    static final String LATEST_GLOBAL_SNAPSHOT = "SELECT " + SNAPSHOT_COLUMNS + """

            FROM score_snapshot s WHERE s.scope_type = 'GLOBAL'
            ORDER BY s.computed_at DESC LIMIT 1""";

    static final String REPOSITORY_NAMESPACE = "SELECT namespace_id FROM source_repository WHERE id = :repositoryId";

    /** Branch scores attached to the jobs of a run (audit page). */
    static final String RUN_JOB_SCORES = "SELECT s.scan_job_id, " + SNAPSHOT_COLUMNS + """

            FROM score_snapshot s JOIN scan_job j ON j.id = s.scan_job_id
            WHERE j.scan_run_id = :runId AND s.scope_type = 'BRANCH'""";

    static final String RECORD_LANGUAGES = """
            UPDATE source_repository SET languages = CAST(:labels AS jsonb), languages_updated_at = now()
            WHERE id = :repositoryId""";
}
