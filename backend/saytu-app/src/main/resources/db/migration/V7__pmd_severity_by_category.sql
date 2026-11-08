-- PMD severity now depends on the rule category (PmdAdapter.severity): the quickstart rule set gives
-- priority 1 to naming and style rules, which were shown as HIGH. Stored findings are aligned here
-- (the category is kept at the end of their description: "PMD category: <name>"); the next audit
-- produces the same values. Priority is not stored, so findings are only ever lowered, never raised.

-- Code Style and Documentation: at most LOW
UPDATE finding SET severity = 'LOW', version = version + 1
WHERE scanner_id = 'pmd' AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
  AND (description LIKE '%PMD category: Code Style' OR description LIKE '%PMD category: Documentation');

-- Best Practices, Design, Performance: at most MEDIUM
UPDATE finding SET severity = 'MEDIUM', version = version + 1
WHERE scanner_id = 'pmd' AND severity IN ('CRITICAL', 'HIGH')
  AND (description LIKE '%PMD category: Best Practices' OR description LIKE '%PMD category: Design'
       OR description LIKE '%PMD category: Performance');

-- Ask the worker to rescore every audited branch from the stored results at its next start (ScoreUpgrade).
INSERT INTO app_setting (key, value, updated_by)
VALUES ('scoring.rescore', '"V7: PMD severity by category"'::jsonb, 'migration V7')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now();
