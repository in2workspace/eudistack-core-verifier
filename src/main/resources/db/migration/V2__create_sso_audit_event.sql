-- M-2: CREATE TABLE sso_audit_event (write-once)
-- Write-once behaviour enforced with trigger that prevents UPDATE/DELETE.

CREATE TABLE IF NOT EXISTS sso_audit_event (
                                               id UUID PRIMARY KEY,
                                               tenant TEXT NOT NULL,
                                               event_type TEXT NOT NULL,
                                               client_id TEXT,
                                               holder_hash TEXT,
                                               message TEXT,
                                               correlation_id TEXT,
                                               occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sso_audit_event_tenant_occurred
    ON sso_audit_event (tenant, occurred_at);

-- Prevent updates/deletes to enforce write-once semantics
DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_proc
        WHERE proname = 'sso_audit_prevent_mods'
    ) THEN

CREATE FUNCTION sso_audit_prevent_mods()
    RETURNS trigger
    LANGUAGE plpgsql
        AS $func$
BEGIN
            RAISE EXCEPTION 'sso_audit_event is write-once: modifications are not allowed';
END;
        $func$;

END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'trg_sso_audit_prevent_mods'
    ) THEN

CREATE TRIGGER trg_sso_audit_prevent_mods
    BEFORE UPDATE OR DELETE
ON sso_audit_event
            FOR EACH ROW
            EXECUTE FUNCTION sso_audit_prevent_mods();

END IF;
END;
$do$;