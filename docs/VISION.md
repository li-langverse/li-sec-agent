# li-sec-agent vision

## Problem

PR review bots optimize for general code quality. Security teams need **consistent, explainable, security-first** feedback with an audit trail and optional on-prem inference.

## Product moat: telemetry-first

The product only makes sense when we **capture data from day one**:

- Every webhook, scan, inference, finding, and comment emits a typed event.
- Usage metering (`lines_scanned`, tokens, tier) ties directly to monetization.
- Human labels (`thumbs_up`, `false_positive`) close the training loop for Qwen and rulepacks.

See [DATA_CAPTURE.md](DATA_CAPTURE.md) — not optional infrastructure.

## Product flow

1. GitHub `pull_request` webhook → verified, `pr_webhook_received`.
2. Fetch diff → `diff_hash` + `lines_scanned` (no raw diff in telemetry by default).
3. Static checks + **on-cluster Qwen** → hashed prompts/responses, token counts.
4. `finding_created` per row → PR comment → `pr_comment_posted`.
5. `usage_metering` rollup → billing export.
6. User feedback → `false_positive_labeled` → training datasets.

## Monetization

- SaaS per-seat / per-org with tier env (`SECAGENT_TIER`).
- Usage-based on `lines_scanned` + `tokens_in/out` from `usage_metering`.
- GitHub Marketplace App install.
- Enterprise on-prem Helm + air-gapped Qwen.
- Optional anonymized findings feed.

## Architecture

Homelab: namespace `secagent-staging`, Qwen on **engine** (NVIDIA GPU, `kubernetes.io/hostname=engine`). blackpearl is control-plane only — **no GPU**.

## Ecosystem

- **li-langverse**: repo host, GPU training, telemetry warehouse.
- **majico**: first GitHub App consumer ([PR_INTEGRATION.md](PR_INTEGRATION.md)).
