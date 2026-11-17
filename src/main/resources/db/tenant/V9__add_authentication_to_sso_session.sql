ALTER TABLE sso_session ADD COLUMN auth_method VARCHAR(16) NOT NULL DEFAULT 'wallet';
ALTER TABLE sso_session ADD CONSTRAINT ck_sso_session_auth_method CHECK (auth_method IN ('wallet', 'x509'));
ALTER TABLE sso_session ADD COLUMN acr TEXT;
ALTER TABLE sso_session ADD COLUMN amr TEXT[];
ALTER TABLE sso_session ADD COLUMN certificate_not_after TIMESTAMPTZ;
