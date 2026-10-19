-- Explicit operator-run migration; protocol artifacts contain no account passwords.
BEGIN;
CREATE SCHEMA IF NOT EXISTS identity_oidc;
CREATE TABLE IF NOT EXISTS identity_oidc.artifacts (
  model text NOT NULL,
  id text NOT NULL,
  payload jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(model,id)
);
CREATE INDEX IF NOT EXISTS artifacts_grant_idx ON identity_oidc.artifacts ((payload->>'grantId'));
CREATE INDEX IF NOT EXISTS artifacts_uid_idx ON identity_oidc.artifacts ((payload->>'uid'));
CREATE INDEX IF NOT EXISTS artifacts_expiry_idx ON identity_oidc.artifacts(expires_at);
COMMIT;
