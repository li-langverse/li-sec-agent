# CWE benchmark database

Synthetic, safe PR-diff scenarios keyed to real CWE ids for **li-sec-agent** model evaluation. Taxonomy comes from the homelab CWE mirror and MITRE REST; scenarios are generated locally (no exploits or live attack hosts).

## Artifacts

| File | Purpose |
|------|---------|
| `eval/cwe-expansion-backlog.json` | Prioritized 50-CWE expansion list (P0/P1/P2) |
| `eval/cwe-mirror-snapshot.json` | Last inventory pull from `cwe.klaut.pro` (969 weaknesses) |
| `eval/cwe-taxonomy.json` | MITRE-enriched metadata per backlog CWE |
| `eval/cwe-database.json` | Master DB: CWE entries + nested scenarios |
| `eval/benchmark-cwe-expanded.json` | Flat `BenchmarkCase[]` for `eval-models.ts` |
| `eval/benchmark-cwe-expanded.sample.json` | First 50 cases (review / CI) |
| `eval/cwe-database.manifest.json` | Counts by CWE, language, harness category |

## Schema (`cwe-database.json`)

```json
{
  "version": 1,
  "generated_at": "ISO-8601",
  "cwe_entries": [
    {
      "cwe_id": "CWE-787",
      "name": "Out-of-bounds Write",
      "priority": "P0",
      "languages": ["c", "cpp", "rust"],
      "scenarios": [
        {
          "scenario_id": "c-cwe-787-buffer-overflow-vuln-000",
          "title": "buffer-overflow",
          "language": "c",
          "category": "injection",
          "diff": "@@ ...",
          "expected": [{ "category": "injection" }],
          "negative": false,
          "cwe_id": "CWE-787",
          "source": "synthetic"
        }
      ]
    }
  ]
}
```

Harness cases use the same fields as `eval/benchmark-multilang.json` (`id`, `language`, `category`, `cwe`, `file_path`, `diff`, `expected`, `negative`).

## Regenerate

```bash
# Full pipeline: mirror inventory → MITRE enrich → scenarios
npm run benchmark:build-cwe-db

# Steps individually
npm run benchmark:cwe-inventory              # stats; add --write-snapshot for eval/cwe-mirror-snapshot.json
npm run benchmark:cwe-enrich                 # eval/cwe-taxonomy.json (~50 REST calls, polite delay)
npm run benchmark:cwe-scenarios              # eval/benchmark-cwe-expanded.json + cwe-database.json

# Optional env
MITRE_DELAY_MS=400                           # default 350ms between MITRE requests
MIN_SCENARIOS_PER_CWE=3                      # floor per backlog CWE
TIER_FILTER=P0                               # only P0 tier from backlog
```

## Run evaluation

```bash
CASE_LIMIT=5 BENCHMARK_PATH=eval/benchmark-cwe-expanded.json npm run eval:models
```

Default multilang corpus remains `eval/benchmark-multilang.json` (840 cases). Set `BENCHMARK_PATH` to switch corpora.

## Current stats (v1)

Regenerate `eval/cwe-database.manifest.json` for live numbers. After the initial v1 build:

- **~235** total scenarios across **50** CWEs
- **~170** positive (vuln-in-diff), **~45** negative (safe / FP probes)
- Languages: C, C++, Rust, Python, JavaScript, TypeScript (per backlog matrix)

## Safety and licensing

- Diffs are minimal synthetic snippets only (no weaponized payloads, no real API keys).
- MITRE CWE names/descriptions: reference data via public REST API.
- Generated scenario JSON: project MIT (li-sec-agent).

See [CWE_BENCHMARK_EXPANSION_PLAN.md](./CWE_BENCHMARK_EXPANSION_PLAN.md) for roadmap (OpenSSF real CVE diffs = Phase 2 extraction).
