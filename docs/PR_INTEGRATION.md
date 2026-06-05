# GitHub PR integration

## GitHub App (recommended)

Create a GitHub App under **li-langverse** (or a dedicated `secagent` app) with:

### Permissions

| Permission | Access | Why |
|------------|--------|-----|
| Pull requests | Read & write | Read diffs, post review comments |
| Contents | Read | Fetch files at `head` SHA |
| Metadata | Read | Repo identity |
| Checks | Read (optional) | Gate on CI later |

### Webhook events

Subscribe to:

- `pull_request` — `opened`, `synchronize`, `reopened`, `ready_for_review`
- `installation` / `installation_repositories` — org onboarding
- `ping` — health

Webhook URL (staging example):

```text
https://secagent.<your-edge-host>/webhooks/github
```

For homelab without public ingress, use **smee.io** or Tailscale funnel temporarily, or run the agent in CI that polls — production uses the same handler path.

### Webhook → agent flow

```mermaid
sequenceDiagram
  participant GH as GitHub
  participant WH as secagent-worker
  participant API as GitHub API
  participant QW as Qwen (Ollama)
  participant DB as Findings DB

  GH->>WH: pull_request (signed)
  WH->>WH: verify HMAC, idempotent delivery_id
  WH->>API: GET pull + diff / compare
  WH->>WH: static scanners (stub)
  WH->>QW: chat/completions (diff excerpt)
  QW-->>WH: JSON findings
  WH->>DB: findings + trace hashes
  WH->>GH: POST review comment / review thread
```

## Review comment format (mitigation-first)

Each finding includes a **Suggested fix** block with optional diff, effort estimate, and references.

```markdown
## SecAgent security review

Found **1** issue with suggested fixes.

| Severity | Category | Location | Issue | Fix effort |
|----------|----------|----------|-------|------------|
| 🟠 high | secrets | `src/auth.ts:42` | Hardcoded API key pattern | low |

### 🟠 Hardcoded API key pattern

| | |
|---|---|
| **Severity** | `high` |
| **Category** | `secrets` |
| **Location** | `src/auth.ts:42` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **Confidence** | 95% |

Literal secret in source may leak via VCS.

**Evidence:**
```
const API_KEY = "sk-live-abc123";
```

#### Suggested fix

**Move secret to environment variable** _(effort: low)_

Load the key from process.env and rotate the exposed credential.

```
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error('API_KEY required');
```

**Alternatives:**
- Use a secret manager (Vault, AWS SM)

**References:**
- https://cwe.mitre.org/data/definitions/798.html
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

---

<sub>Review id: `8b2e…` · [Open findings](https://secagent.internal/reviews/8b2e…) · Powered by SecAgent</sub>
```

- **Summary comment** — always posted (table + per-issue blocks).
- **Inline comments** — set `PR_INLINE_COMMENTS=true` when file + line are known; uses Pull Request Review API `path` + `line` (or `position` when webhook provides patch offset).

Formatter: `src/pr-comment.ts`. UX rubric: [MITIGATION_REVIEWS.md](./MITIGATION_REVIEWS.md).

## Environment variables

See `.env.example`. Required for production webhook path:

- `GITHUB_WEBHOOK_SECRET`
- `GITHUB_APP_ID` + private key (or `GITHUB_TOKEN` for PAT-only dev)

## Majico integration (PR #70 and beyond)

1. Install the GitHub App on `cap-jmk-launchpad/majico` (or li-langverse fork).
2. Point webhook to the worker Service — in-cluster: `http://secagent-worker.secagent-staging.svc.cluster.local:8787/webhooks/github`.
3. From majico CI (optional): call `POST` with dry-run header for preview reviews on `pull_request` label `security-agent`.
4. Store `SECAGENT_REVIEW_URL` in majico staging secrets for deep links from Studio / admin.

No CodeRabbit-style full UI in MVP — comments + DB link only.

## Idempotency

Key: `(delivery_id)` from `X-GitHub-Delivery`. Replays with same delivery return `202` without duplicate findings.

## Security

- Verify `X-Hub-Signature-256` always in production.
- Scope installation tokens per repo.
- Never log raw `GITHUB_APP_PRIVATE_KEY` or full diffs at `info` level.
