-- Phase 4: scan orchestration (run planning, job queue, results).

-- A run records WHAT was requested (scope); the worker's planner expands it into jobs
-- (one per repository x branch) because resolving branches may need calls to the Git platforms.
ALTER TABLE scan_run
    ADD COLUMN scope            JSONB         NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN planned_at       TIMESTAMPTZ,
    ADD COLUMN cancel_requested BOOLEAN       NOT NULL DEFAULT FALSE,
    -- repositories of the scope that produced no job (no branch, already queued...), with reasons
    ADD COLUMN planning_notes   JSONB         NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN error_message    VARCHAR(2000);

CREATE INDEX ix_scan_run_unplanned ON scan_run (created_at) WHERE planned_at IS NULL AND status = 'QUEUED';

ALTER TABLE scan_job
    ADD COLUMN checkout_bytes    BIGINT,
    ADD COLUMN checkout_files    INTEGER,
    ADD COLUMN findings_count    INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN new_findings      INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN resolved_findings INTEGER NOT NULL DEFAULT 0;

-- Findings listing: newest first per repository / branch, and filter on the reporting scanner.
CREATE INDEX ix_finding_last_seen ON finding (repository_id, branch, last_seen_at DESC);
CREATE INDEX ix_finding_occurrence_finding ON finding_occurrence (finding_id, scanner_id);
