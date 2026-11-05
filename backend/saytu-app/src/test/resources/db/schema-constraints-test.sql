-- Schema constraint checks, executed after V1 by scripts/verify-schema.sh (plain psql, no JVM needed)
-- and mirrored by FlywaySchemaIT (Testcontainers). Every block must end with "ok".
\set ON_ERROR_STOP on
SET client_min_messages = warning;

CREATE OR REPLACE FUNCTION pg_temp.expect_failure(sql text, label text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE sql;
    RAISE EXCEPTION 'expected failure but statement succeeded: %', label;
EXCEPTION
    WHEN check_violation OR unique_violation OR foreign_key_violation OR not_null_violation OR raise_exception THEN
        IF SQLERRM LIKE 'expected failure%' THEN RAISE; END IF;
        RETURN 'ok - ' || label;
END;
$$;

BEGIN;

-- seed scanners present
SELECT CASE WHEN count(*) = 10 THEN 'ok - 10 scanners seeded' ELSE 'FAIL' END FROM scanner_config;
SELECT CASE WHEN NOT enabled THEN 'ok - dependency-check disabled by default' ELSE 'FAIL' END
FROM scanner_config WHERE scanner_id = 'dependency-check';

INSERT INTO git_connection (id, name, provider_type, base_url, created_by)
VALUES ('00000000-0000-0000-0000-000000000001', 'gl', 'GITLAB', 'https://gitlab.example.org', 'test');

SELECT pg_temp.expect_failure(
    $q$INSERT INTO git_connection (name, provider_type, base_url, token_ciphertext, created_by)
       VALUES ('x', 'GITLAB', 'https://h', '\x00', 'test')$q$, 'token without key id rejected');
SELECT pg_temp.expect_failure(
    $q$INSERT INTO git_connection (name, provider_type, base_url, created_by) VALUES ('y', 'SVN', 'https://h', 't')$q$,
    'unknown provider rejected');

SELECT pg_temp.expect_failure(
    $q$UPDATE git_connection SET verify_tls = FALSE WHERE name = 'gl'$q$, 'TLS verification cannot be disabled (V2)');
UPDATE git_connection SET last_test_status = 'BLOCKED_BY_POLICY', last_test_warnings = '{"plain http"}' WHERE name = 'gl';
SELECT 'ok - BLOCKED_BY_POLICY test status accepted (V2)';
SELECT pg_temp.expect_failure(
    $q$UPDATE git_connection SET last_test_status = 'MAYBE' WHERE name = 'gl'$q$, 'unknown test status rejected (V2)');

INSERT INTO source_repository (id, connection_id, external_id, full_name, name, clone_url)
VALUES ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', '42', 'g/app', 'app',
        'https://gitlab.example.org/g/app.git');

SELECT pg_temp.expect_failure(
    $q$INSERT INTO source_repository (connection_id, external_id, full_name, name, clone_url)
       VALUES ('00000000-0000-0000-0000-000000000001', '43', 'g/b', 'b', 'https://oauth2:glpat-x@gitlab.example.org/g/b.git')$q$,
    'clone url with embedded credentials rejected');

INSERT INTO repository_branch (repository_id, name) VALUES
    ('00000000-0000-0000-0000-000000000010', 'feature/ABC-12_login'),
    ('00000000-0000-0000-0000-000000000010', 'release/2026.11');
SELECT 'ok - valid branch names accepted (V3)';
SELECT pg_temp.expect_failure(format($q$INSERT INTO repository_branch (repository_id, name)
       VALUES ('00000000-0000-0000-0000-000000000010', %L)$q$, n), 'branch name rejected (V3): ' || n)
FROM unnest(ARRAY['-x', 'a..b', 'a b', 'a~1', 'x.lock', 'feat/.hidden', 'main/', '/main', 'a//b', 'HEAD',
                  'a@{1}', 'main.', E'a\nb', 'a:b', 'a*', 'a[']) AS n;

INSERT INTO scan_run (id, trigger_type, requested_by) VALUES ('00000000-0000-0000-0000-000000000100', 'MANUAL', 'test');
INSERT INTO scan_job (id, scan_run_id, repository_id, branch)
VALUES ('00000000-0000-0000-0000-000000001000', '00000000-0000-0000-0000-000000000100',
        '00000000-0000-0000-0000-000000000010', 'main');

SELECT pg_temp.expect_failure(
    $q$INSERT INTO scan_job (scan_run_id, repository_id, branch)
       VALUES ('00000000-0000-0000-0000-000000000100', '00000000-0000-0000-0000-000000000010', 'main')$q$,
    'only one active job per repository branch');

INSERT INTO scanner_execution (id, scan_job_id, scanner_id, status)
VALUES ('00000000-0000-0000-0000-000000010000', '00000000-0000-0000-0000-000000001000', 'gitleaks', 'SUCCEEDED');

INSERT INTO finding (id, repository_id, branch, fingerprint, type, severity, scanner_id, rule_id, title)
VALUES ('00000000-0000-0000-0000-000000100000', '00000000-0000-0000-0000-000000000010', 'main',
        repeat('a', 64), 'SECRET', 'HIGH', 'gitleaks', 'generic-api-key', 'Generic API key');

SELECT pg_temp.expect_failure(
    $q$INSERT INTO finding (repository_id, branch, fingerprint, type, severity, scanner_id, rule_id, title)
       VALUES ('00000000-0000-0000-0000-000000000010', 'main', repeat('a', 64), 'SECRET', 'HIGH', 'gitleaks', 'r', 't')$q$,
    'duplicate fingerprint per branch rejected');
SELECT pg_temp.expect_failure(
    $q$INSERT INTO finding (repository_id, branch, fingerprint, type, severity, scanner_id, rule_id, title)
       VALUES ('00000000-0000-0000-0000-000000000010', 'main', repeat('Z', 64), 'SECRET', 'HIGH', 'gitleaks', 'r', 't')$q$,
    'non-hex fingerprint rejected');
SELECT pg_temp.expect_failure(
    $q$UPDATE finding SET status = 'FALSE_POSITIVE' WHERE id = '00000000-0000-0000-0000-000000100000'$q$,
    'triage without reason/author rejected');

UPDATE finding SET status = 'FALSE_POSITIVE', status_reason = 'test fixture', status_changed_by = 'alice'
WHERE id = '00000000-0000-0000-0000-000000100000';
SELECT 'ok - triage with reason accepted';

INSERT INTO finding_occurrence (finding_id, scanner_execution_id, scan_job_id, scanner_id, rule_id, reported_severity, file_path, start_line)
VALUES ('00000000-0000-0000-0000-000000100000', '00000000-0000-0000-0000-000000010000',
        '00000000-0000-0000-0000-000000001000', 'gitleaks', 'generic-api-key', 'HIGH', 'config.yml', 3);
SELECT 'ok - occurrence recorded';

SELECT pg_temp.expect_failure(
    $q$INSERT INTO score_snapshot (scope_type, coverage_percent, reliability, formula_version, repository_id)
       VALUES ('GLOBAL', 50, 'LOW', 'v1', '00000000-0000-0000-0000-000000000010')$q$,
    'GLOBAL score must not reference a repository');
INSERT INTO score_snapshot (scope_type, repository_id, branch, security_score, coverage_percent, reliability, formula_version)
VALUES ('BRANCH', '00000000-0000-0000-0000-000000000010', 'main', 87.5, 80, 'MEDIUM', 'v1');
SELECT 'ok - branch score accepted';
SELECT pg_temp.expect_failure(
    $q$INSERT INTO score_snapshot (scope_type, security_score, coverage_percent, reliability, formula_version)
       VALUES ('GLOBAL', 120, 100, 'HIGH', 'v1')$q$, 'score above 100 rejected');

SELECT pg_temp.expect_failure(
    $q$INSERT INTO scan_schedule_target (schedule_id) VALUES (gen_random_uuid())$q$,
    'schedule target needs exactly one of namespace/repository');

INSERT INTO audit_event (actor_subject, action) VALUES ('alice', 'TEST');
SELECT pg_temp.expect_failure($q$UPDATE audit_event SET action = 'X'$q$, 'audit_event update forbidden');
SELECT pg_temp.expect_failure($q$DELETE FROM audit_event$q$, 'audit_event delete forbidden');

-- cascade: deleting the connection removes repositories, jobs, findings
DELETE FROM git_connection WHERE id = '00000000-0000-0000-0000-000000000001';
SELECT CASE WHEN (SELECT count(*) FROM finding) = 0 AND (SELECT count(*) FROM scan_job) = 0
            THEN 'ok - cascade delete from connection' ELSE 'FAIL - cascade' END;

ROLLBACK;
