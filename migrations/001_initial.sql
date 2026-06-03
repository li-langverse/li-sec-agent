-- SecAgent MVP schema (Postgres-compatible; SQLite uses subset via data layer)

CREATE TABLE IF NOT EXISTS pr_reviews (
  id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL,
  repo_full_name TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  head_sha TEXT NOT NULL,
  diff_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_pr_reviews_repo_pr ON pr_reviews (repo_full_name, pr_number);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  review_id TEXT NOT NULL REFERENCES pr_reviews (id),
  file_path TEXT,
  line_start INTEGER,
  line_end INTEGER,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT,
  cwe TEXT,
  source TEXT NOT NULL,
  model_id TEXT,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  latency_ms INTEGER,
  feedback_label TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_review ON findings (review_id);

CREATE TABLE IF NOT EXISTS model_traces (
  id TEXT PRIMARY KEY,
  review_id TEXT NOT NULL REFERENCES pr_reviews (id),
  model_id TEXT NOT NULL,
  prompt_hash TEXT NOT NULL,
  response_hash TEXT NOT NULL,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  latency_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_model_traces_review ON model_traces (review_id);
