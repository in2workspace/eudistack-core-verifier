-- Undo for M-1: drop sso_session (safe idempotent)
DROP TABLE IF EXISTS sso_session CASCADE;

