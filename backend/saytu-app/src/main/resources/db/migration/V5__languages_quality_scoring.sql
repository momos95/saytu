-- Phase 5: language detection, quality tools per language, scoring.

-- New quality tools, chosen per detected language.
ALTER TABLE scanner_config DROP CONSTRAINT scanner_config_scanner_id_check;
ALTER TABLE scanner_config ADD CONSTRAINT scanner_config_scanner_id_check CHECK (scanner_id IN (
    'opengrep', 'trivy', 'gitleaks', 'pmd', 'checkstyle', 'dependency-check', 'eslint', 'phpcs', 'cppcheck', 'sqlfluff'));

INSERT INTO scanner_config (scanner_id, enabled, timeout_seconds, cpu_seconds, memory_mb, settings) VALUES
    ('eslint',   TRUE, 900, 1800, 2048, '{}'),
    ('phpcs',    TRUE, 900, 1800, 1024, '{"standard": "PSR12"}'),
    ('cppcheck', TRUE, 900, 1800, 2048, '{"jobs": "2"}'),
    ('sqlfluff', TRUE, 600, 1200, 1024, '{"dialect": "ansi"}')
ON CONFLICT (scanner_id) DO NOTHING;

-- Checkstyle and PMD now run with SAYTU's configuration / PMD quickstart (phase 1 placeholders).
UPDATE scanner_config SET settings = '{}'::jsonb WHERE scanner_id = 'checkstyle' AND settings = '{"config": "bundled-sun-checks"}'::jsonb;
UPDATE scanner_config SET settings = '{"threads": "2"}'::jsonb WHERE scanner_id = 'pmd' AND settings = '{"ruleset": "bundled-quickstart"}'::jsonb;

-- Languages of each analysed checkout: {"java": {"files": 120, "bytes": 450000}, ...}
ALTER TABLE scan_job ADD COLUMN languages JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Labels of the repository, from its latest analysed branch: ["java", "typescript", ...] (most present first)
ALTER TABLE source_repository
    ADD COLUMN languages            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN languages_updated_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_repository_languages CHECK (jsonb_typeof(languages) = 'array');

-- Scores: latest snapshot per scope is read often (lists, dashboard).
CREATE INDEX ix_score_snapshot_branch ON score_snapshot (repository_id, branch, computed_at DESC) WHERE scope_type = 'BRANCH';
CREATE INDEX ix_score_snapshot_latest ON score_snapshot (scope_type, computed_at DESC);

-- Formula v1 (docs/scoring.md). Fields left out keep their default.
UPDATE app_setting SET value = '{
  "version": "v1",
  "securityWeights": {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0},
  "securityScale": 50,
  "criticalCap": 59,
  "qualityWeights": {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0.1},
  "qualityScale": 50,
  "bytesPerLine": 35,
  "securityShare": 0.6,
  "minCoverage": 40
}'::jsonb, updated_by = 'migration V5', updated_at = now()
WHERE key = 'scoring.formula';
