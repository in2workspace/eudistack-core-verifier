-- M-1: CREATE TABLE sso_session
-- Creates table with PK id, indexes and partial unique constraint for active sessions.
-- Idempotent so it is safe to run manually; Flyway will run once.

CREATE TABLE IF NOT EXISTS sso_session (
                                           id TEXT PRIMARY KEY,
                                           tenant TEXT NOT NULL,
                                           holder_hash TEXT NOT NULL,
                                           established_at TIMESTAMPTZ NOT NULL,
                                           expires_at TIMESTAMPTZ NOT NULL,
                                           last_used_at TIMESTAMPTZ NOT NULL,
                                           state VARCHAR(32) NOT NULL
    );

-- Index for searches by tenant, holder and state
CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_holder_state
    ON sso_session (tenant, holder_hash, state);

-- Index for tenant-expiration scans
CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_expires
    ON sso_session (tenant, expires_at);

-- Index for idle timeout checks (🔧 añadido para last_used_at)
CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_last_used
    ON sso_session (tenant, last_used_at);

-- Partial unique index: only one ACTIVE session per (tenant, holder_hash)
CREATE UNIQUE INDEX IF NOT EXISTS uq_sso_session_tenant_holder_active
    ON sso_session (tenant, holder_hash)
    WHERE state = 'ACTIVE';