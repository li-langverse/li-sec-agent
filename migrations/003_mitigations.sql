-- Finding evidence/confidence + mitigation records

ALTER TABLE findings ADD COLUMN evidence TEXT;
ALTER TABLE findings ADD COLUMN confidence REAL;

CREATE TABLE IF NOT EXISTS mitigations (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings (id),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  suggested_patch TEXT,
  references_json TEXT NOT NULL DEFAULT '[]',
  effort TEXT NOT NULL,
  alternative_approaches_json TEXT NOT NULL DEFAULT '[]',
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mitigations_finding ON mitigations (finding_id);

ALTER TABLE telemetry_events ADD COLUMN mitigation_count INTEGER;
ALTER TABLE telemetry_events ADD COLUMN mitigation_hash TEXT;
