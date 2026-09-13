-- State is intentionally opaque at rest: authorization codes and assertions are
-- never stored, only one-way hashes and token identifiers needed for revocation.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agent_identities (
  id TEXT PRIMARY KEY NOT NULL,
  identity_type TEXT NOT NULL CHECK (identity_type IN ('anonymous', 'service_auth', 'identity_assertion')),
  scopes_json TEXT NOT NULL,
  resource TEXT,
  client_id TEXT,
  subject TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS agent_identities_subject_idx ON agent_identities(subject);

CREATE TABLE IF NOT EXISTS agent_claims (
  id TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES agent_identities(id),
  user_code_hash TEXT NOT NULL UNIQUE,
  device_code_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'user_verified', 'approved', 'denied', 'expired')),
  scopes_json TEXT NOT NULL,
  resource TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  interval_seconds INTEGER NOT NULL,
  last_poll_at INTEGER,
  verification_attempts INTEGER NOT NULL DEFAULT 0,
  user_code_used_at INTEGER,
  grant_used_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS agent_claims_expiry_idx ON agent_claims(expires_at);

CREATE TABLE IF NOT EXISTS assertion_replays (
  id TEXT PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS assertion_replays_expiry_idx ON assertion_replays(expires_at);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key TEXT PRIMARY KEY NOT NULL,
  window_started_at INTEGER NOT NULL,
  count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS issued_tokens (
  id TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES agent_identities(id),
  subject TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  resource TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS issued_tokens_expiry_idx ON issued_tokens(expires_at);

CREATE TABLE IF NOT EXISTS event_subscribers (
  id TEXT PRIMARY KEY NOT NULL,
  url TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
);

CREATE TABLE IF NOT EXISTS revocation_events (
  id TEXT PRIMARY KEY NOT NULL,
  token_id TEXT NOT NULL UNIQUE REFERENCES issued_tokens(id),
  subject TEXT NOT NULL,
  occurred_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS event_deliveries (
  id TEXT PRIMARY KEY NOT NULL,
  event_id TEXT NOT NULL REFERENCES revocation_events(id),
  subscriber_id TEXT NOT NULL REFERENCES event_subscribers(id),
  status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_attempt_at INTEGER,
  receipt TEXT
);

CREATE INDEX IF NOT EXISTS event_deliveries_due_idx ON event_deliveries(status, next_attempt_at);
