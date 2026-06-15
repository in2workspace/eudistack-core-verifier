-- V2__M-2_create_sso_audit_event.sql
-- Migration M-2: Create table sso_audit_event (write-once). Per-tenant schema via ${tenant} placeholder.

BEGIN;

CREATE SCHEMA IF NOT EXISTS "${tenant}";
SET search_path TO "${tenant}";

-- Audit table (append-only / write-once)
CREATE TABLE IF NOT EXISTS sso_audit_event (
    id UUID PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    tenant TEXT NOT NULL,
    client_id TEXT,
    holder_hash TEXT,
    outcome TEXT,
    correlation_id TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Function to prevent updates/deletes (write-once)
CREATE OR REPLACE FUNCTION prevent_sso_audit_modification()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'sso_audit_event is write-once and cannot be modified or deleted';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger to block UPDATE and DELETE on the audit table
DROP TRIGGER IF EXISTS trg_prevent_sso_audit_mod ON sso_audit_event;
CREATE TRIGGER trg_prevent_sso_audit_mod
    BEFORE UPDATE OR DELETE ON sso_audit_event
    FOR EACH ROW EXECUTE FUNCTION prevent_sso_audit_modification();

COMMIT;

-- NOTE: The function+trigger make the table effectively write-once at the DB level.
-- To append events, INSERTs are allowed; UPDATE/DELETE will raise an exception.
-- Run per-tenant by setting Flyway placeholder `tenant` appropriately.

