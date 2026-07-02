-- M-6: CREATE TABLE sso_eligible_client
-- Catálogo de clientes OIDC elegibles para SSO por tenant.
-- Escritura idempotente: INSERT ... ON CONFLICT DO NOTHING garantiza EC-04.
-- Aislamiento multi-tenant: columna tenant + search_path por conexión (defense in depth).

CREATE TABLE IF NOT EXISTS sso_eligible_client (
    tenant     TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    PRIMARY KEY (tenant, client_id)
);

CREATE INDEX IF NOT EXISTS idx_sso_eligible_client_tenant
    ON sso_eligible_client (tenant);
