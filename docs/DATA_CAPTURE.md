# Data capture & telemetry

Telemetry is **core product infrastructure**, not a later phase. Every review path emits structured events for billing, training, and compliance.

## Event types

| Event | When | Key fields |
|-------|------|------------|
| `pr_webhook_received` | GitHub `pull_request` webhook accepted | `delivery_id`, `repo`, `pr_number` |
| `diff_fetched` | Patch retrieved (or stub) | `diff_hash`, `lines_scanned` |
| `static_scan_started` / `static_scan_completed` | Rulepack / Semgrep phase | `findings_count` |
| `qwen_inference_started` / `completed` / `failed` | LLM call | `prompt_hash`, `response_hash`, `tokens_in/out`, `latency_ms` |
| `finding_created` | Row persisted | `finding_id`, `severity`, `category`, `source` |
| `pr_comment_posted` | Review comment on PR | `findings_count` |
| `user_feedback` | Thumbs up/down on a finding | `finding_id`, `feedback` |
| `false_positive_labeled` | Explicit FP label | `finding_id` |
| `review_completed` / `review_failed` | Pipeline terminal state | metering rollup |

Schema: [schemas/telemetry-event.schema.json](../schemas/telemetry-event.schema.json)

## Storage

| Layer | MVP | Production |
|-------|-----|------------|
| Events | SQLite `telemetry_events` | Postgres or ClickHouse |
| Metering | SQLite `usage_metering` | Same warehouse + billing export |
| Findings | `findings` + `model_traces` | Retained per tenant policy |

Migrations: `migrations/001_initial.sql`, `migrations/002_telemetry.sql` — column types map cleanly to Postgres `UUID`/`TIMESTAMPTZ` and ClickHouse `LowCardinality(String)` / `DateTime64`.

## Retention (defaults)

| Dataset | Staging | Production SaaS |
|---------|---------|-----------------|
| `telemetry_events` | 90 days | 1 year (configurable) |
| `usage_metering` | 2 years | 7 years (billing) |
| Raw prompts/responses | **not stored** — hashes only | Enterprise opt-in encrypted blob |
| Findings | 90 days | Tenant-defined |

Purge job (future): `DELETE FROM telemetry_events WHERE occurred_at < now() - interval '90 days'`.

## Privacy

- **Diffs:** store `diff_hash` (SHA-256 of normalized patch), not full diff in telemetry by default.
- **LLM:** store `prompt_hash` / `response_hash`; optional redacted excerpt in `payload_json` for debug tiers only.
- **Redaction:** `src/telemetry/privacy.ts` strips tokens, PEM blocks, `ghp_` / `github_pat_` patterns before DB/OTLP.
- **Logs:** structured JSON only; no raw webhook bodies at `info`.

## Pipeline

```
Webhook → TelemetryPipeline.emit() → SQLite + stdout JSON log
                                    → OtelBridge (if OTEL_EXPORTER_OTLP_ENDPOINT set)
```

Code entry points:

- `src/webhooks/github.ts` — `pr_webhook_received`
- `src/index.ts` — diff, findings, comment, metering, review terminal events
- `src/llm/qwen-client.ts` — inference started/completed/failed
- `src/orchestrator/scanner.ts` — static scan events

## Usage metering (monetization)

Table `usage_metering` per `review_id`:

- `org_id`, `repo_full_name`, `pr_number`, `tier`
- `lines_scanned`, `tokens_in`, `tokens_out`, `findings_count`
- `static_findings`, `qwen_findings`

Env: `SECAGENT_ORG_ID`, `SECAGENT_TIER` (`free` | `team` | `business` | `enterprise` | `on_prem`).

## Training loop

1. Ship agent → capture findings + `user_feedback` / `false_positive_labeled`.
2. Export labeled rows (finding_id, diff_hash, category, feedback) to li-langverse training pipelines.
3. Fine-tune Qwen or train reranker; deploy new model tag in `QWEN_MODEL`.
4. Compare FP rate via `telemetry_events` dashboards.

## OpenTelemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://otel-collector.signoz:4318`). Stub exporter posts span-shaped JSON to `/v1/traces`. Replace `src/telemetry/otel.ts` with full SDK when collector is live.

K8s: [infra/k8s/staging/servicemonitor.yaml](../infra/k8s/staging/servicemonitor.yaml) (Prometheus scrape stub).

## Feedback API (MVP)

```http
POST /feedback/{findingId}
Content-Type: application/json

{ "review_id": "uuid", "label": "thumbs_down" | "false_positive" | ... }
```

Persists `user_feedback` or `false_positive_labeled` telemetry events.
