-- EUD-149 production-readiness: reemplaza la caché local no distribuida
-- (CacheStore<JsonNode> ssoSessionCredentialCache) por un snapshot cifrado (AES-256-GCM,
-- AesGcmSsoCredentialCipherAdapter) persistido en la misma fila/transacción de sso_session.
-- Nullable: sesiones establecidas antes de esta migración, o sin credencial que snapshotear,
-- simplemente no permiten reutilización silenciosa (fail-closed a login_required).
ALTER TABLE sso_session ADD COLUMN credential_snapshot BYTEA;
