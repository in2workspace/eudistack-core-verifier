ALTER TABLE sso_session ADD COLUMN last_used_at TIMESTAMPTZ;
UPDATE sso_session SET last_used_at = established_at WHERE last_used_at IS NULL;
ALTER TABLE sso_session ALTER COLUMN last_used_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_last_used
    ON sso_session (tenant, last_used_at);
