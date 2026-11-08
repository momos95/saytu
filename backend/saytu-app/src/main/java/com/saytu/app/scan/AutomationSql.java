package com.saytu.app.scan;

/**
 * SQL of phase 7: schedules, webhook endpoints and their outbox, job comparison, AI explanations.
 * Kept as constants so {@code scripts/verify-scan-sql.sh} runs them on a real PostgreSQL.
 */
final class AutomationSql {

    private AutomationSql() {
    }

    // ------------------------------------------------------------------ schedules

    static final String SCHEDULE_COLUMNS = """
            s.id, s.name, s.cron_expression, s.time_zone, s.scope, s.enabled, s.next_fire_at, s.last_fired_at,
            s.last_run_id, s.last_outcome, s.created_by, s.created_at, s.updated_at,
            coalesce((SELECT array_agg(t.repository_id::text) FROM scan_schedule_target t
                      WHERE t.schedule_id = s.id AND t.repository_id IS NOT NULL), '{}') AS repository_ids,
            coalesce((SELECT array_agg(t.namespace_id::text) FROM scan_schedule_target t
                      WHERE t.schedule_id = s.id AND t.namespace_id IS NOT NULL), '{}') AS namespace_ids,
            (SELECT r.status FROM scan_run r WHERE r.id = s.last_run_id) AS last_run_status""";

    static final String LIST_SCHEDULES = "SELECT " + SCHEDULE_COLUMNS + " FROM scan_schedule s ORDER BY s.name";

    static final String GET_SCHEDULE = "SELECT " + SCHEDULE_COLUMNS + " FROM scan_schedule s WHERE s.id = :id";

    static final String INSERT_SCHEDULE = """
            INSERT INTO scan_schedule (id, name, cron_expression, time_zone, scope, enabled, skip_unchanged, next_fire_at, created_by)
            VALUES (:id, :name, :cron, :timeZone, :scope, :enabled, FALSE, :nextFireAt, :user)""";

    static final String UPDATE_SCHEDULE = """
            UPDATE scan_schedule SET name = :name, cron_expression = :cron, time_zone = :timeZone, scope = :scope,
                   enabled = :enabled, next_fire_at = :nextFireAt, updated_at = now()
            WHERE id = :id""";

    static final String DELETE_SCHEDULE = "DELETE FROM scan_schedule WHERE id = :id";

    static final String DELETE_SCHEDULE_TARGETS = "DELETE FROM scan_schedule_target WHERE schedule_id = :id";

    static final String INSERT_SCHEDULE_REPOSITORY = """
            INSERT INTO scan_schedule_target (schedule_id, repository_id) VALUES (:id, :targetId)""";

    static final String INSERT_SCHEDULE_NAMESPACE = """
            INSERT INTO scan_schedule_target (schedule_id, namespace_id) VALUES (:id, :targetId)""";

    /** Due schedules, locked so two workers never fire the same one. */
    static final String CLAIM_DUE_SCHEDULES = "SELECT " + SCHEDULE_COLUMNS + """

            FROM scan_schedule s
            WHERE s.enabled AND s.next_fire_at IS NOT NULL AND s.next_fire_at <= now()
            ORDER BY s.next_fire_at
            LIMIT 20
            FOR UPDATE OF s SKIP LOCKED""";

    static final String SCHEDULE_HAS_ACTIVE_RUN = """
            SELECT EXISTS (SELECT 1 FROM scan_run r WHERE r.schedule_id = :id AND r.status IN ('QUEUED', 'RUNNING'))""";

    static final String INSERT_SCHEDULED_RUN = """
            INSERT INTO scan_run (trigger_type, schedule_id, requested_by, status, scope)
            VALUES ('SCHEDULED', :id, :requestedBy, 'QUEUED', CAST(:scope AS jsonb))
            RETURNING id""";

    static final String RECORD_FIRING = """
            UPDATE scan_schedule SET last_fired_at = now(), next_fire_at = :nextFireAt, last_outcome = :outcome,
                   last_run_id = coalesce(CAST(:runId AS uuid), last_run_id)
            WHERE id = :id""";

    /** Repositories selected for audit inside the given organisations (resolved when the schedule fires). */
    static final String TARGETS_IN_NAMESPACES = """
            SELECT r.id FROM source_repository r
            WHERE r.namespace_id = ANY(CAST(:namespaceIds AS uuid[])) AND r.removed_at IS NULL AND NOT r.archived""";

    // ------------------------------------------------------------------ webhooks

    static final String WEBHOOK_COLUMNS = """
            w.id, w.name, w.url, w.format, w.min_severity, w.events, w.enabled, w.created_by, w.created_at, w.updated_at,
            (w.secret_ciphertext IS NOT NULL) AS has_secret,
            (SELECT d.status FROM webhook_delivery d WHERE d.endpoint_id = w.id ORDER BY d.created_at DESC LIMIT 1) AS last_status,
            (SELECT max(d.delivered_at) FROM webhook_delivery d WHERE d.endpoint_id = w.id) AS last_delivered_at""";

    static final String LIST_WEBHOOKS = "SELECT " + WEBHOOK_COLUMNS + " FROM webhook_endpoint w ORDER BY w.name";

    static final String GET_WEBHOOK = "SELECT " + WEBHOOK_COLUMNS + " FROM webhook_endpoint w WHERE w.id = :id";

    static final String INSERT_WEBHOOK = """
            INSERT INTO webhook_endpoint (id, name, url, format, secret_ciphertext, secret_key_id, min_severity, events, enabled, created_by)
            VALUES (:id, :name, :url, :format, :secretCiphertext, :secretKeyId, :minSeverity, CAST(:events AS varchar[]), :enabled, :user)""";

    static final String UPDATE_WEBHOOK = """
            UPDATE webhook_endpoint SET name = :name, url = :url, format = :format, min_severity = :minSeverity,
                   events = CAST(:events AS varchar[]), enabled = :enabled, updated_at = now()
            WHERE id = :id""";

    static final String UPDATE_WEBHOOK_SECRET = """
            UPDATE webhook_endpoint SET secret_ciphertext = :secretCiphertext, secret_key_id = :secretKeyId, updated_at = now()
            WHERE id = :id""";

    static final String DELETE_WEBHOOK = "DELETE FROM webhook_endpoint WHERE id = :id";

    static final String WEBHOOK_SECRET = "SELECT secret_ciphertext, secret_key_id FROM webhook_endpoint WHERE id = :id";

    /** Enabled endpoints subscribed to an event. */
    static final String SUBSCRIBED_WEBHOOKS = """
            SELECT w.id, w.format, w.min_severity FROM webhook_endpoint w
            WHERE w.enabled AND CAST(:event AS varchar) = ANY(w.events)""";

    /** Findings created by a job (first seen in it) that are still open, worst first. */
    static final String NEW_FINDINGS_OF_JOB = """
            SELECT f.id, f.severity, f.type, f.scanner_id, f.rule_id, f.title, f.file_path, f.start_line, f.cve_id,
                   f.package_name, f.package_version
            FROM finding f
            WHERE f.first_seen_job_id = :jobId AND f.status = 'OPEN'
            ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                     f.title""";

    static final String JOB_CONTEXT = """
            SELECT j.id, j.scan_run_id, j.branch, j.status, j.commit_sha, j.findings_count, j.new_findings, j.resolved_findings,
                   r.id AS repository_id, r.full_name
            FROM scan_job j JOIN source_repository r ON r.id = j.repository_id
            WHERE j.id = :jobId""";

    static final String ENQUEUE_DELIVERY = """
            INSERT INTO webhook_delivery (endpoint_id, event_type, payload)
            VALUES (:endpointId, :event, CAST(:payload AS jsonb))
            RETURNING id""";

    /** Due deliveries, locked for this worker; only enabled endpoints are sent. */
    static final String CLAIM_DELIVERIES = """
            SELECT d.id, d.endpoint_id, d.event_type, d.payload::text AS payload, d.attempts, w.url, w.format,
                   w.secret_ciphertext, w.secret_key_id
            FROM webhook_delivery d JOIN webhook_endpoint w ON w.id = d.endpoint_id
            WHERE d.status = 'PENDING' AND d.next_attempt_at <= now() AND w.enabled
            ORDER BY d.next_attempt_at
            LIMIT 20
            FOR UPDATE OF d SKIP LOCKED""";

    static final String DELIVERY_SUCCEEDED = """
            UPDATE webhook_delivery SET status = 'DELIVERED', attempts = attempts + 1, delivered_at = now(),
                   last_http_status = :httpStatus, last_error = NULL
            WHERE id = :id""";

    static final String DELIVERY_FAILED = """
            UPDATE webhook_delivery SET attempts = attempts + 1, last_http_status = :httpStatus, last_error = :error,
                   status = CASE WHEN attempts + 1 >= :maxAttempts THEN 'FAILED' ELSE 'PENDING' END,
                   next_attempt_at = now() + make_interval(secs => :retryInSeconds)
            WHERE id = :id""";

    static final String LIST_DELIVERIES = """
            SELECT d.id, d.event_type, d.status, d.attempts, d.last_http_status, d.last_error, d.created_at, d.delivered_at,
                   d.next_attempt_at
            FROM webhook_delivery d WHERE d.endpoint_id = :id
            ORDER BY d.created_at DESC
            LIMIT 20""";

    // ------------------------------------------------------------------ comparison of two jobs

    /** Previous finished job of the same branch. */
    static final String PREVIOUS_JOB = """
            SELECT p.id FROM scan_job j
            JOIN scan_job p ON p.repository_id = j.repository_id AND p.branch = j.branch
                           AND p.status IN ('SUCCEEDED', 'PARTIAL') AND p.finished_at < j.finished_at
            WHERE j.id = :jobId
            ORDER BY p.finished_at DESC
            LIMIT 1""";

    static final String COMPARE_JOB = """
            SELECT j.id, j.repository_id, r.full_name, j.branch, j.status, j.commit_sha, j.finished_at
            FROM scan_job j JOIN source_repository r ON r.id = j.repository_id
            WHERE j.id = :jobId""";

    /** Scanner status of a job (to tell "fixed" from "not checked"). */
    static final String COMPARE_EXECUTIONS = """
            SELECT scanner_id, status, tool_version FROM scanner_execution WHERE scan_job_id = :jobId ORDER BY scanner_id""";

    /** Findings seen by a job: finding id, scanners that reported it in this job. */
    static final String FINDINGS_SEEN_BY_JOB = """
            SELECT o.finding_id, array_agg(DISTINCT o.scanner_id) AS scanners
            FROM finding_occurrence o WHERE o.scan_job_id = :jobId
            GROUP BY o.finding_id""";

    static final String FINDINGS_BY_IDS = "SELECT " + ScanSql.FINDING_COLUMNS + """

            FROM finding f JOIN source_repository s ON s.id = f.repository_id
            WHERE f.id = ANY(CAST(:ids AS uuid[]))
            ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                     f.title, f.id""";

    /** Latest branch score computed for a job (rescores add newer snapshots for the same job). */
    static final String JOB_SCORE = "SELECT " + ScoreSql.SNAPSHOT_COLUMNS + """

            FROM score_snapshot s WHERE s.scope_type = 'BRANCH' AND s.scan_job_id = :jobId
            ORDER BY s.computed_at DESC LIMIT 1""";

    // ------------------------------------------------------------------ AI explanations

    static final String GET_REMEDIATION = """
            SELECT provider_id, content::text AS content, created_at FROM finding_remediation
            WHERE finding_id = :findingId AND generative ORDER BY created_at DESC LIMIT 1""";

    static final String SAVE_REMEDIATION = """
            INSERT INTO finding_remediation (finding_id, provider_id, generative, content)
            VALUES (:findingId, :providerId, TRUE, CAST(:content AS jsonb))
            ON CONFLICT (finding_id, provider_id) DO UPDATE SET content = EXCLUDED.content, created_at = now()""";

    static final String GET_SETTING = "SELECT value::text FROM app_setting WHERE key = :key";

    static final String PUT_SETTING = """
            INSERT INTO app_setting (key, value, updated_by) VALUES (:key, CAST(:value AS jsonb), :user)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()""";
}
