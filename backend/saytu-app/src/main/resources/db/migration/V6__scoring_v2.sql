-- Phase 6b: scoring formula v2 (docs/scoring.md) and severity of committed secrets.

-- 1. Formula v2: hyperbolic security curve, weights per kind of issue, diminishing returns per group.
--    The worker rescores every audited branch from the stored results at its next start (ScoreUpgrade).
UPDATE app_setting SET value = '{
  "version": "v2",
  "securityWeights": {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0},
  "securityScale": 100,
  "criticalCap": 59,
  "qualityWeights": {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0.1},
  "qualityScale": 50,
  "bytesPerLine": 35,
  "securityShare": 0.6,
  "minCoverage": 40,
  "securityCurve": "HYPERBOLIC",
  "categoryFactors": {"CODE": 1, "SECRET": 1, "DEPENDENCY": 1, "CONFIGURATION": 0.5},
  "noFixFactor": 0.5,
  "diminishingReturns": true
}'::jsonb, updated_by = 'migration V6', updated_at = now()
WHERE key = 'scoring.formula';

-- 2. A secret committed to Git is exposed to everyone who can clone: never below HIGH; CRITICAL when its
--    format identifies the issuer (same list as GitleaksAdapter.CRITICAL_PREFIXES). New scans apply the
--    same rule, so the next audit keeps these values.
UPDATE finding SET severity = 'CRITICAL', version = version + 1
WHERE type = 'SECRET' AND scanner_id = 'gitleaks' AND severity <> 'CRITICAL'
  AND lower(rule_id) LIKE ANY (ARRAY['private-key%', 'aws-%', 'gcp-%', 'azure-%', 'alibaba-%', 'github-%', 'gitlab-%',
      'bitbucket-%', 'stripe-%', 'square-%', 'paypal-%', 'slack-%', 'twilio-%', 'sendgrid-%', 'mailgun-%', 'openai-%',
      'anthropic-%', 'heroku-%', 'digitalocean-%', 'npm-access-token%', 'pypi-upload-token%', 'rubygems-%',
      'hashicorp-%', 'vault-%', 'doppler-%', 'databricks-%', 'shopify-%', 'dropbox-%']);

UPDATE finding SET severity = 'HIGH', version = version + 1
WHERE type = 'SECRET' AND severity IN ('MEDIUM', 'LOW', 'INFO');
