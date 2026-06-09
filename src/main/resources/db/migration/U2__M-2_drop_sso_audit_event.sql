-- U2__M-2_drop_sso_audit_event.sql
-- Undo/Drop script for M-2 (create sso_audit_event). Use with care.

BEGIN;

CREATE SCHEMA IF NOT EXISTS "${tenant}";
SET search_path TO "${tenant}";

-- Drop trigger and function first
DROP TRIGGER IF EXISTS trg_prevent_sso_audit_mod ON sso_audit_event;
DROP FUNCTION IF EXISTS prevent_sso_audit_modification();

DROP TABLE IF EXISTS sso_audit_event CASCADE;

COMMIT;

