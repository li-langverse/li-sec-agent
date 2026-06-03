-- Telemetry + usage metering (Postgres/ClickHouse-friendly types; SQLite MVP)

CREATE TABLE IF NOT EXISTS telemetry_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  org_id TEXT NOT NULL,
  installation_id TEXT,
  repo_full_name TEXT,
  pr_number INTEGER,
  review_id TEXT NOT NULL,
  delivery_id TEXT,
  commit_sha TEXT,
  diff_hash TEXT,
  lines_scanned INTEGER,
  tokens_in INTEGER,
  tokens_out INTEGER,
  findings_count INTEGER,
  tier TEXT NOT NULL DEFAULT 'free',
  model_id TEXT,
  prompt_hash TEXT,
  response_hash TEXT,
  latency_ms INTEGER,
  finding_id TEXT,
  feedback TEXT,
  severity TEXT,
  category TEXT,
  source TEXT,
  error_code TEXT,
  error_message_redacted TEXT,
  trace_id TEXT,
  span_id TEXT,
  payload_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_telemetry_review ON telemetry_events (review_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_org_time ON telemetry_events (org_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry_events (event_type, occurred_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_repo_pr ON telemetry_events (repo_full_name, pr_number);

CREATE TABLE IF NOT EXISTS usage_metering (
  id TEXT PRIMARY KEY,
  review_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  repo_full_name TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  tier TEXT NOT NULL,
  lines_scanned INTEGER NOT NULL DEFAULT 0,
  tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0,
  findings_count INTEGER NOT NULL DEFAULT 0,
  static_findings INTEGER NOT NULL DEFAULT 0,
  qwen_findings INTEGER NOT NULL DEFAULT 0,
  recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (review_id)
);
