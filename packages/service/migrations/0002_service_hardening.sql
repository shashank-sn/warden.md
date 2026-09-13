-- Privacy-safe registration outcomes support incident review without retaining
-- assertions, access tokens, device codes, service secrets, or key material.
CREATE TABLE IF NOT EXISTS identity_attempt_audit (
  id TEXT PRIMARY KEY NOT NULL,
  identity_type TEXT NOT NULL CHECK (identity_type IN ('anonymous', 'service_auth', 'identity_assertion')),
  client_id TEXT,
  subject TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'rejected')),
  error_code TEXT,
  occurred_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS identity_attempt_audit_occurred_idx
  ON identity_attempt_audit(occurred_at);
