-- V1__M-1_create_sso_session.sql
-- Migration M-1: Create table sso_session with indexes and partial unique constraint
-- Designed to be executed per-tenant. Set Flyway placeholder `tenant` to the desired schema name.

BEGIN;

-- Create tenant schema if it does not exist
CREATE SCHEMA IF NOT EXISTS "${tenant}";

-- Ensure we operate in the tenant schema
SET search_path TO "${tenant}";

-- Create table
CREATE TABLE IF NOT EXISTS sso_session (
    id UUID PRIMARY KEY,
    tenant TEXT NOT NULL,
    holder_hash TEXT NOT NULL,
    established_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    state VARCHAR(20) NOT NULL,
    client_id TEXT,
    correlation_id TEXT
);

-- Indexes for lookup and cleanup
CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_holder_state ON sso_session (tenant, holder_hash, state);
CREATE INDEX IF NOT EXISTS idx_sso_session_tenant_expires_at ON sso_session (tenant, expires_at);

-- Partial unique index: only one ACTIVE session per (tenant, holder_hash)
CREATE UNIQUE INDEX IF NOT EXISTS uniq_sso_session_tenant_holder_active ON sso_session (tenant, holder_hash) WHERE (state = 'ACTIVE');

COMMIT;

-- NOTE: This migration is written to be idempotent when executed multiple times for the same tenant.
-- To run for multiple tenants, invoke Flyway with the placeholder `tenant` set to each schema name.
-- Example (CLI):
-- flyway -placeholders.tenant=tenant_a migrate
-- flyway -placeholders.tenant=tenant_b migrate

