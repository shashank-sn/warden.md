-- The production Durable Object owns the compare-and-set transition; D1 retains the evidence ledger.
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  action_descriptor TEXT NOT NULL,
  requested_scope TEXT NOT NULL,
  granted_scope TEXT NOT NULL,
  dpop_thumbprint TEXT NOT NULL,
  state TEXT NOT NULL,
  issued_at INTEGER,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER,
  evidence_id TEXT
);

CREATE INDEX IF NOT EXISTS grants_by_expiry ON grants(expires_at);
CREATE INDEX IF NOT EXISTS grants_by_subject ON grants(subject_id);

CREATE TABLE IF NOT EXISTS broker_audit_events (
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES grants(id),
  event_type TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  safe_detail TEXT
);

CREATE INDEX IF NOT EXISTS broker_audit_events_by_grant ON broker_audit_events(grant_id, created_at);
