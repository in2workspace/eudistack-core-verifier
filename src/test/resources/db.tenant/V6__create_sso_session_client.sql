-- ADR-108 (DELTA-02 EUDISTACK-551): rastreo de actividad por aplicativo de una sesión SSO.
-- Poblada de forma aditiva por EstablishSsoSessionWorkflow (US-02) y ReuseSsoSessionWorkflowImpl (US-03).
-- Clave por session_id (no por holder_hash): hay una sola sesión ACTIVE por holder y clavar por
-- sesión evita arrastrar filas de una sesión previa superseded del mismo holder.
-- FK ON DELETE CASCADE: el GC de sesiones (hard-delete 24h post-expiración) limpia las filas hijas
-- sin lógica adicional.

CREATE TABLE IF NOT EXISTS sso_session_client (
    session_id     TEXT NOT NULL REFERENCES sso_session(id) ON DELETE CASCADE,
    tenant         TEXT NOT NULL,
    client_id      TEXT NOT NULL,
    first_seen_at  TIMESTAMPTZ NOT NULL,
    last_used_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (session_id, client_id)
);

-- Índice de soporte para findClientsBySession(sessionId, tenant)
CREATE INDEX IF NOT EXISTS idx_sso_session_client_tenant_session
    ON sso_session_client (tenant, session_id);
