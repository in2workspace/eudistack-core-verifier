-- M-1: CREATE TABLE sso_session
-- Creates table with PK id, indexes and partial unique constraint for active sessions.
-- Idempotent (IF NOT EXISTS) so it is safe to run manually; Flyway will run once.

CREATE TABLE IF NOT EXISTS sso_session (
    id UUID PRIMARY KEY,
    tenant TEXT NOT NULL,
    holder_hash TEXT NOT NULL,
    established_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    state VARCHAR(32) NOT NULL
);

-- Index for searches by tenant, holder and state
CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_holder_state ON sso_session (tenant, holder_hash, state);

-- Index for tenant-expiration scans
CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_expires ON sso_session (tenant, expires_at);

-- Partial unique constraint: only one ACTIVE session per (tenant, holder_hash)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_class t ON c.conrelid = t.oid
        WHERE t.relname = 'sso_session' AND c.contype = 'u' AND c.conname = 'uq_sso_session_tenant_holder_active'
    ) THEN
        ALTER TABLE sso_session ADD CONSTRAINT uq_sso_session_tenant_holder_active UNIQUE (tenant, holder_hash) WHERE (state = 'ACTIVE');
    END IF;
END$$;

