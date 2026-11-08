-- Phase 7: scheduled audits, webhook alerts, local AI (optional).

-- Schedules: outcome of the last firing, shown in the settings page.
ALTER TABLE scan_schedule
    ADD COLUMN last_run_id   UUID REFERENCES scan_run (id) ON DELETE SET NULL,
    ADD COLUMN last_outcome  VARCHAR(500),
    ADD COLUMN updated_at    TIMESTAMPTZ NOT NULL DEFAULT now();
-- not implemented in this version (needs a remote lookup before cloning): kept false so nothing is skipped silently
ALTER TABLE scan_schedule ALTER COLUMN skip_unchanged SET DEFAULT FALSE;
UPDATE scan_schedule SET skip_unchanged = FALSE;
CREATE INDEX ix_scan_run_schedule ON scan_run (schedule_id, created_at DESC) WHERE schedule_id IS NOT NULL;

-- Webhooks: payload format (GENERIC JSON, or SLACK-compatible {"text": ...} for Slack, Mattermost, Rocket.Chat).
ALTER TABLE webhook_endpoint
    ADD COLUMN format      VARCHAR(16) NOT NULL DEFAULT 'GENERIC' CHECK (format IN ('GENERIC', 'SLACK')),
    ADD COLUMN updated_at  TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE webhook_endpoint
    ADD CONSTRAINT ck_webhook_url CHECK (url ~ '^https?://[^\s]+$'),
    ADD CONSTRAINT ck_webhook_events CHECK (events <@ ARRAY['NEW_FINDINGS', 'SCAN_COMPLETED', 'TEST']::varchar[] AND cardinality(events) > 0);
CREATE INDEX ix_webhook_delivery_endpoint ON webhook_delivery (endpoint_id, created_at DESC);

-- Local AI (Ollama): disabled until an administrator enables it; nothing is sent outside the server.
INSERT INTO app_setting (key, value, updated_by)
VALUES ('ai.ollama', '{"enabled": false, "baseUrl": "http://ollama:11434", "model": "qwen2.5-coder:7b", "timeoutSeconds": 120}'::jsonb,
        'migration V8')
ON CONFLICT (key) DO NOTHING;
