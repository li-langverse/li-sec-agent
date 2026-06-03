# Qwen model evaluation (li-sec-agent)

Security PR review benchmark for on-cluster Ollama on **engine** (NVIDIA RTX 3060, 12 GB VRAM).

## Ollama registry tags (verified 2026-06-03)

| Role | Ollama tag | Disk size | Notes |
|------|------------|-----------|-------|
| **Baseline (current)** | `qwen2.5-coder:3b` | 1.9 GB | Code-tuned; staging default |
| **9B class (Qwen 3.5)** | `qwen3.5:9b` | 6.6 GB (Q4_K_M) | Also `qwen3.5:9b-q4_K_M`, `qwen3.5:9b-q8_0` (11 GB) |
| **~14B dense (fits 12 GB)** | `qwen3:14b` | 9.3 GB (Q4_K_M) | Closest dense step-up; no exact Qwen 3.5 20B |
| **~20B target (OOM on 3060)** | `qwen3.5:27b` | 17 GB | Does not fit 12 GB VRAM at default quant |
| **~20B alt (OOM on 3060)** | `qwen3:30b-a3b` | 19 GB | MoE; active ~3B params but weights still ~19 GB |
| **~20B alt (OOM on 3060)** | `qwen3:32b` | 20 GB | Dense 32B Q4 |
| **Coding 14B fallback** | `qwen2.5-coder:14b` | 9.0 GB | If 3.5 unavailable; code-specific |

There is **no Qwen 3.5 ~20B** tag on the official library. Sizes jump **9b → 27b → 35b → 122b**. For “20B class” we test **`qwen3:14b`** (fits) and attempt **`qwen3.5:27b`** (expected OOM).

Other useful tags:

- `qwen3:8b` — 5.2 GB (older gen, smaller than 3.5 9B)
- `qwen2.5:14b` — 9.0 GB (general instruct, not coder)
- `qwen3.5:35b-a3b-int4` — 20 GB (MoE; still too large for 12 GB)

Sources: [ollama.com/library/qwen3.5](https://ollama.com/library/qwen3.5), [qwen3 tags](https://ollama.com/library/qwen3/tags), [qwen2.5-coder tags](https://ollama.com/library/qwen2.5-coder/tags).

## GPU feasibility (RTX 3060 12 GB)

| Model | Weight VRAM (approx) | Fits 12 GB? | Context headroom |
|-------|----------------------|-------------|------------------|
| `qwen2.5-coder:3b` | ~2 GB | Yes | Large |
| `qwen3.5:9b` | ~6.5 GB Q4 | Yes | Moderate (256K max ctx; use ≤8K for reviews) |
| `qwen3:14b` | ~9.3 GB Q4 | Yes (tight) | Small — keep prompts short |
| `qwen2.5-coder:14b` | ~9 GB Q4 | Yes (tight) | Small |
| `qwen3.5:27b` | ~17 GB Q4 | **No** | OOM unless CPU offload / smaller quant |
| `qwen3:30b-a3b` | ~19 GB Q4 | **No** | MoE weights still exceed VRAM |
| `qwen3:32b` | ~20 GB Q4 | **No** | — |

Ollama loads one model at a time by default. Pod memory limit is **8 Gi RAM** — very large models may also hit host RAM during load even if VRAM were sufficient.

**Blockers for ~20B on RTX 3060:**

1. Smallest official ~20B-class tags (`qwen3.5:27b`, `qwen3:30b-a3b`, `qwen3:32b`) need **17–20 GB** VRAM at Q4.
2. No official Qwen 3.5 tag between 9B and 27B.
3. Aggressive quants (Q2/Q3) or CPU offload are possible but slow and not in default Ollama tags.
4. Upgrade path: **24 GB GPU** (3090/4090) or run 27B with partial CPU offload.

## Benchmark harness

```bash
# From repo root — hits cluster NodePort by default
npm run eval:models

# Custom models / in-cluster URL
QWEN_BASE_URL=http://qwen-ollama.secagent-staging.svc.cluster.local:11434/v1 \
MODELS=qwen2.5-coder:3b,qwen3.5:9b,qwen3:14b \
npm run eval:models
```

- **Cases:** `eval/benchmark-cases.json` — 18 synthetic diffs (SQLi, secrets, XSS, authz, crypto, SSRF, safe-code negatives). For real CVE-backed expansion see [OFFICIAL_EVAL_BENCHMARKS.md](./OFFICIAL_EVAL_BENCHMARKS.md).
- **Metrics:** precision, recall, F1 (category match), false-positive rate on negative cases, p50/p95 latency, token counts.
- **Output:** `eval/results/*.json` (gitignored) + console summary table.

Scoring matches production scanner categories (`injection`, `authz`, `secrets`, `crypto`, `config`, …).

## Pull models on cluster

```bash
ssh blackpearl
kubectl -n secagent-staging exec -it deploy/qwen-ollama -- ollama pull qwen3.5:9b
kubectl -n secagent-staging exec -it deploy/qwen-ollama -- ollama pull qwen3:14b
# Expected to fail on 12 GB:
kubectl -n secagent-staging exec -it deploy/qwen-ollama -- ollama pull qwen3.5:27b
```

## Eval results

See latest run in `eval/results/summary-*.json`. Re-run after model pulls to refresh numbers below.

<!-- EVAL_RESULTS_START -->
| Model | Status | F1 | Prec | Recall | FP rate | Neg pass | p50 ms | VRAM MiB |
|-------|--------|-----|------|--------|---------|----------|--------|----------|
| `qwen2.5-coder:3b` | ok | 0.00 | 1.00 | 0.00 | 0.00 | 1.00 | 64 | 2936 |
| `qwen2.5-coder:14b` | ok | 0.615 | 0.571 | 0.667 | 0.33 | 0.67 | 2952 | 11016 |
| `qwen3.5:9b` | ok | **0.690** | 0.588 | **0.833** | 0.50 | 0.50 | 8880 | 8397 |
| `qwen3.5:27b` | skipped | — | — | — | — | — | — | OOM (~17 GB weights > 12 GB VRAM) |

Run: 2026-06-03, API `http://192.168.10.33:31434/v1`, Ollama **0.24.0**, engine RTX 3060 12 GB.
<!-- EVAL_RESULTS_END -->

## Recommendation

**Staging default:** `qwen3.5:9b` (set in `configmap.yaml`). Highest benchmark F1/recall on 12 GB GPU with ~8.4 GB VRAM loaded; ~9 s median latency per diff.

| | `qwen2.5-coder:3b` | `qwen3.5:9b` | `qwen2.5-coder:14b` | `qwen3.5:27b` |
|--|---------------------|--------------|---------------------|---------------|
| Quality (F1) | Poor (0.00) | **Best (0.69)** | Good (0.62) | N/A (OOM) |
| VRAM | ~3 GB | ~8.4 GB | ~11 GB (tight) | ~17 GB weights |
| Latency p50 | ~64 ms | ~8.9 s | ~3.0 s | — |
| Coding focus | Yes | General multimodal | Yes | — |

**Fast/cheap path:** `qwen2.5-coder:3b` only if you accept near-zero vulnerability recall (not recommended for production reviews).

**Code-tuned alternative:** `qwen2.5-coder:14b` for lower latency when you can spare ~11 GB VRAM.

**27b blocker on RTX 3060:** `qwen3.5:27b` Q4 weights are ~17 GB; with KV cache, load exceeds 12 GB VRAM (14b already uses ~11 GB at runtime). Needs ≥24 GB GPU or CPU offload.
