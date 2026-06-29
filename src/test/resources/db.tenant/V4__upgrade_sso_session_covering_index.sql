-- V4: promote idx_sso_session_tenant_expires to a true covering index.
--
-- The V3 index (tenant, expires_at) is a regular B-tree index; PostgreSQL
-- cannot perform index-only scans on queries that also need state or id.
--
-- Adding INCLUDE (state, id) allows the planner to resolve:
--   WHERE tenant = ? AND expires_at > now() AND state = 'ACTIVE'
-- entirely from the index, without a heap fetch (NFR-P-549-01 / R-3).
--
-- DROP + CREATE runs inside the Flyway transaction so the window without
-- the index is invisible to concurrent readers in PostgreSQL.

DROP INDEX IF EXISTS idx_sso_session_tenant_expires;

CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_expires
    ON sso_session (tenant, expires_at)
    INCLUDE (state, id);
