# Reference security benchmark database

**Mission:** Provide the de facto reference corpus for **F-measure**, **fine-tuning**, and **model evaluation** of security-focused PR/diff review — merging the 840-case multilang synthetic base, CWE-expanded scenarios, OpenSSF CVE metadata, and scalable synthetic expansion with provenance, versioning, and train/eval/holdout splits.

**Location:** `eval/reference-database/`

---

## Artifacts

| Path | Purpose |
|------|---------|
| `schema.json` | JSON Schema v1 for `ReferenceCase` + `corpusManifest` |
| `manifest.json` | Version, sources[], stats, split policy, roadmap |
| `corpus-v1.json` | Canonical merged corpus (chunked if >8 MB) |
| `ossf-subset.json` | OpenSSF CVE Benchmark import (generated) |
| `synthetic-expanded.json` | +500 synthetic expansion (generated) |
| `baselines.json` | Model F1 baselines from smoke/full eval |
| `finetune-train.jsonl` | SFT export (messages format) |

Legacy corpora remain for regression:

- `eval/benchmark-multilang.json` — 840 cases, 22 CWE families
- `eval/benchmark-cwe-expanded.json` — ~235 cases, 50 CWE backlog

---

## Schema v1 (`ReferenceCase`)

Each case extends the harness `BenchmarkCase` with canonical metadata:

| Field | Description |
|-------|-------------|
| `ref_id` | Stable id: `ref-{source}-{legacy-id}` |
| `id` | Upstream harness id |
| `language` | `c` \| `cpp` \| `rust` \| `python` \| `javascript` \| `typescript` |
| `category` | Scenario archetype slug |
| `cwe` | `CWE-###` when known |
| `file_path`, `diff`, `expected`, `negative` | Same as `eval-models.ts` |
| `source` | Provenance enum (see manifest `licensing`) |
| `provenance` | `{ source, upstream_id?, cve?, repository?, license?, notes? }` |
| `split` | `train` (70%) \| `eval` (20%) \| `holdout` (10%) |
| `difficulty` | `easy` \| `medium` \| `hard` (heuristic from diff size) |
| `content_hash` | Dedup key: `sha256(file_path + diff)[0:16]` |
| `harness_category` | Mapped bucket: injection, authz, secrets, … |

Split assignment is **deterministic**: `sha256(ref_id)[0] mod 100`.

---

## Build pipeline

```bash
# 1) Optional: fetch OpenSSF CVE subset (network)
npm run benchmark:fetch-ossf

# 2) Synthetic expansion (+500 target)
npm run benchmark:expand-reference

# 3) Merge + dedupe + manifest
npm run benchmark:build-reference-db

# 4) Fine-tune JSONL (train split default: all; use SPLIT=train)
npm run export:finetune-jsonl
```

Full chain:

```bash
npm run benchmark:reference-v1
```

Environment knobs:

| Variable | Default | Effect |
|----------|---------|--------|
| `OSSF_LIMIT` | 75 | Max CVE JSON files to fetch |
| `OSSF_USE_GIT` | off | Real `git diff` when `OSSF_CACHE_DIR` cloned |
| `TARGET_EXTRA` | 500 | Synthetic expansion size cap |
| `MIN_SCENARIOS_PER_CWE` | 5 | Positives per backlog CWE |
| `NEGATIVE_RATIO` | 0.3 | ~30% negatives in expansion |
| `CHUNK_MB` | 8 | Split `corpus-v1.json` if larger |

---

## Evaluation

```bash
# Smoke 20 on reference corpus
CASE_LIMIT=20 BENCHMARK_PATH=eval/reference-database/corpus-v1.json MODELS=qwen3.5:9b npm run eval:models

# Optional 100-case slice
CASE_LIMIT=100 BENCHMARK_PATH=eval/reference-database/corpus-v1.json MODELS=qwen3.5:9b npm run eval:models

# Holdout-only (filter in future harness; today use manifest stats + manual CASE_IDS)
```

Record results in `eval/reference-database/baselines.json` and `eval/summaries/`.

**840-case full eval status:** As of 2026-06-04, `eval/results/full-840-qwen35-9b-20260604-054054.log` shows progress only to **~75/840** — not complete. Resume with `CASE_OFFSET=75`.

---

## Fine-tuning export

`scripts/export-finetune-jsonl.ts` emits OpenAI-style **messages** JSONL:

- **system:** security reviewer instructions (same as production scanner)
- **user:** file path, language, CWE, fenced unified diff
- **assistant:** JSON array of findings (or `[]` for negatives)

```bash
SPLIT=train npm run export:finetune-jsonl
# → eval/reference-database/finetune-train.jsonl
```

Use `metadata.ref_id` / `split` for filtering; do not train on `holdout` rows.

---

## Licensing matrix

| Source | License | Redistribution |
|--------|---------|------------------|
| Multilang / CWE / reference synthetic | MIT (li-sec-agent) | Yes |
| MITRE CWE ids/names | MITRE terms | Taxonomy reference |
| OpenSSF CVE Benchmark | MIT metadata | Yes; per-repo OSS for code excerpts |
| PrimeVul / CVEfixes | MIT / CC BY 4.0 | Planned import; attribute |
| CyberSecEval | MIT | Adapted snippets only (no full benchmark) |
| NIST Juliet | Public domain sample | Synthetic port, not full corpus |
| OWASP Benchmark | GPL-2.0 | **Metadata only** — no Java copied |

---

## Comparison to other benchmarks

| Benchmark | Real CVE | PR diff | Multilang | Negatives | Our use |
|-----------|----------|---------|-----------|-----------|---------|
| **Reference DB (this)** | Partial (OSSF) | Yes | 6 langs | ~30% | Primary F1 + SFT |
| Multilang 840 | Synthetic | Yes | 6 | ~30% | Merged into reference |
| OpenSSF CVE Bench | Yes | Yes (JS/TS) | No | Patch as neg | Imported subset |
| PrimeVul / JitVul | Yes | Partial | C/C++ heavy | Pairs | Phase G import |
| CyberSecEval | Mixed | No | N/A | N/A | Gen-risk only |
| OWASP Benchmark | Synthetic | Files | Java | N/A | Metadata only |
| Juliet | Synthetic | Functions | C/C++ | N/A | Sample port |

---

## Roadmap

See **[REFERENCE_DATABASE_ROADMAP.md](./REFERENCE_DATABASE_ROADMAP.md)** for phased targets (v1→v4), work packages, worker responsibilities, and done criteria.

| Version | Target cases | Work |
|---------|-------------|------|
| **v1** (current) | **1,410** | Multilang + CWE + OSSF subset — **done** |
| v2 | 3,000 | OSSF git diffs (218 CVEs), PrimeVul 50 pairs |
| v3 | 5,000 | 100 CWEs × 5 scenarios × 6 langs |
| v4 | 8,000+ | Juliet sample, CyberSecEval ports, holdout gate |

---

## Homelab worker

Background expansion runs on **blackpearl** k3s (`secagent-staging` namespace).

| Item | Value |
|------|-------|
| CronJob | `reference-corpus-expander` — every **6 hours** (`0 */6 * * *`) |
| PVC | `reference-corpus-pvc` (5Gi) → mount `/data/corpus` |
| Image | `li-sec-agent-reference-worker:staging` |
| ConfigMap | `reference-expander-env` — `TARGET_CASES=5000`, batch sizes |

### Deploy

```bash
# From repo root (builds on blackpearl, imports to k3s, applies manifests, runs test job)
bash scripts/deploy-reference-worker.sh
```

Or manually:

```bash
ssh -i ~/Documents/Programming/beelink-cleanup/homelab s4il0r@192.168.10.41
kubectl apply -k /tmp/li-sec-agent-reference-worker/k8s/
kubectl -n secagent-staging create job --from=cronjob/reference-corpus-expander reference-corpus-expander-manual
kubectl -n secagent-staging logs -f job/reference-corpus-expander-manual
```

### Check progress

```bash
# Worker state + case count
kubectl -n secagent-staging exec -it deploy/secagent-worker -- cat /data/corpus/worker-state.json 2>/dev/null \
  || kubectl -n secagent-staging run inspect --rm -it --restart=Never --image=busybox \
     --overrides='...'  # mount reference-corpus-pvc

# Progress log (JSONL events)
cat /data/corpus/expansion-progress.jsonl   # inside PVC via debug pod

# Canonical corpus for eval
/data/corpus/corpus-latest.json
/data/corpus/manifest-latest.json
```

Each cycle logs `cases before → after` and writes `worker-state.json` with `current_cases`, `cycle`, `finished`.

Optional `GH_TOKEN` secret (`reference-expander-secret`) for future git push export — not required for PVC-only MVP.

Manifests: `infra/k8s/reference-worker/`

---

## Related docs

- [CWE_BENCHMARK_EXPANSION_PLAN.md](./CWE_BENCHMARK_EXPANSION_PLAN.md)
- [OFFICIAL_EVAL_BENCHMARKS.md](./OFFICIAL_EVAL_BENCHMARKS.md)
- [MULTILANG_BENCHMARK.md](./MULTILANG_BENCHMARK.md)
- [MODEL_EVAL.md](./MODEL_EVAL.md)
