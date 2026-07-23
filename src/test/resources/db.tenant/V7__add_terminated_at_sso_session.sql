-- US-06 (EUDISTACK-551): columna requerida por terminateActive() (SsoSessionRepositoryPort).
-- Nullable: la mayoria de sesiones nunca transitan por Single Logout (expiran o son superseded).
ALTER TABLE sso_session ADD COLUMN terminated_at TIMESTAMPTZ;
