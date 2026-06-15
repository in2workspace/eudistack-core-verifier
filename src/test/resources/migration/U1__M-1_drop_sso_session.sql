-- U1__M-1_drop_sso_session.sql
-- Undo/Drop script for M-1 (create sso_session). This file can be used to drop the table for a tenant.
-- NOTE: Flyway community does not automatically run undo scripts. Use with care.

BEGIN;

CREATE SCHEMA IF NOT EXISTS "${tenant}";
SET search_path TO "${tenant}";

DROP TABLE IF EXISTS sso_session CASCADE;

COMMIT;

