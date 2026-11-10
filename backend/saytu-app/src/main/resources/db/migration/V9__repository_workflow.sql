-- Branch and release hygiene of each repository (Git flow), refreshed by every audit from the remote refs:
-- production branch main/master on the latest version tag, and a develop branch (WorkflowCheck).
ALTER TABLE source_repository
    ADD COLUMN workflow_status      VARCHAR(8) CHECK (workflow_status IN ('PASS', 'WARN', 'FAIL')),
    ADD COLUMN workflow_report      JSONB,
    ADD COLUMN workflow_checked_at  TIMESTAMPTZ,
    ADD COLUMN workflow_error       VARCHAR(600);
