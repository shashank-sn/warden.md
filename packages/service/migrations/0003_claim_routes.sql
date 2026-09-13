-- A hash-only routing index selects the registration-owned Durable Object for
-- device-code polling and user-code completion without requiring identity_id.
CREATE TABLE IF NOT EXISTS claim_routes (
  claim_id TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES agent_identities(id),
  user_code_hash TEXT NOT NULL UNIQUE,
  device_code_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS claim_routes_expiry_idx ON claim_routes(expires_at);
