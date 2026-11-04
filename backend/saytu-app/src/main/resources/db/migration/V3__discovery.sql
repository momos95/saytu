-- Phase 3: discovery of namespaces, repositories and branches.

-- Outcome of the last namespace discovery of a connection
ALTER TABLE git_connection
    ADD COLUMN last_discovery_at      TIMESTAMPTZ,
    ADD COLUMN last_discovery_status  VARCHAR(32),
    ADD COLUMN last_discovery_message VARCHAR(1000);

-- Items no longer returned by the platform are flagged, not deleted: selections and history survive
-- a transient permission change, and the UI can show "removed from the platform".
ALTER TABLE git_namespace
    ADD COLUMN removed_at                TIMESTAMPTZ,
    ADD COLUMN added_manually            BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN repositories_synced_at    TIMESTAMPTZ,
    ADD COLUMN repositories_sync_status  VARCHAR(32),
    ADD COLUMN repositories_sync_message VARCHAR(1000),
    ADD COLUMN repositories_truncated    BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE source_repository
    ADD COLUMN removed_at TIMESTAMPTZ;

CREATE INDEX ix_git_namespace_connection ON git_namespace (connection_id, full_path);
CREATE INDEX ix_source_repository_ns_name ON source_repository (namespace_id, lower(full_name));

-- Branch names follow git check-ref-format (also validated by BranchNames in the application):
-- no leading '-', no '..', '@{', '//', control characters, space ~ ^ : ? * [ \ ; no leading '/' or
-- trailing '/' or '.'; no component starting with '.' or ending with '.lock'.
ALTER TABLE repository_branch ADD CONSTRAINT ck_repository_branch_name CHECK (
    length(name) BETWEEN 1 AND 255
    AND name !~ '^-'
    AND name !~ '\.\.|@\{|//'
    AND name !~ '[[:cntrl:] ~^:?*\[\\]'
    AND name !~ '^/|/$|\.$'
    AND name !~ '(^|/)\.'
    AND name !~ '\.lock(/|$)'
    AND name NOT IN ('@', 'HEAD'));
