-- Phase 2: connection test results are richer (identity, server version, token expiry) and a new
-- outcome exists for destinations refused by SAYTU's own policy (SSRF guard, local root).

ALTER TABLE git_connection
    ADD COLUMN token_expires_at        TIMESTAMPTZ,
    ADD COLUMN last_test_identity      VARCHAR(255),
    ADD COLUMN last_test_server_version VARCHAR(255),
    ADD COLUMN last_test_warnings      TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE git_connection DROP CONSTRAINT git_connection_last_test_status_check;
ALTER TABLE git_connection ADD CONSTRAINT git_connection_last_test_status_check
    CHECK (last_test_status IN ('OK', 'AUTHENTICATION_FAILED', 'INSUFFICIENT_PERMISSIONS', 'RATE_LIMITED',
                                'NOT_FOUND', 'UNREACHABLE', 'TLS_ERROR', 'SERVER_ERROR', 'UNEXPECTED_RESPONSE',
                                'BLOCKED_BY_POLICY'));

-- TLS verification can no longer be disabled (an internal CA is trusted through SAYTU_GIT_CA_BUNDLE).
UPDATE git_connection SET verify_tls = TRUE WHERE NOT verify_tls;
ALTER TABLE git_connection ADD CONSTRAINT ck_git_connection_verify_tls CHECK (verify_tls);
