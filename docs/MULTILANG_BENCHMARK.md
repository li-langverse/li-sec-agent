# Multilanguage security benchmark corpus

Original minimal PR-style unified diffs for **li-sec-agent** model evaluation. Patterns are inspired by CWE Top 25 (2024), OWASP categories, OpenSSF CVE Benchmark (JS/TS commit-diff style), and CWE-Bench-Java *families* — **not** copied from GPL OWASP Benchmark Java sources.

## Scale

| Metric | Value |
|--------|------:|
| Total cases | 840 |
| Positive (vuln in diff) | 588 (70.0%) |
| Negative (safe / false-positive probes) | 252 (30.0%) |
| Languages | c, cpp, rust, python, javascript, typescript |
| Target per language | 140 |

### Per-language counts

| Language | Cases |
|----------|------:|
| c | 140 |
| cpp | 140 |
| rust | 140 |
| python | 140 |
| javascript | 140 |
| typescript | 140 |

## Taxonomy (language × category)

| Language | Category | CWE | Positive | Negative | Total |
|----------|----------|-----|----------|----------|------:|
| c | buffer-overflow | CWE-787 | 13 | 5 | 18 |
| c | command-injection | CWE-78 | 12 | 5 | 17 |
| c | format-string | CWE-134 | 13 | 5 | 18 |
| c | hardcoded-secrets | CWE-798 | 12 | 5 | 17 |
| c | integer-overflow | CWE-190 | 12 | 6 | 18 |
| c | null-deref | CWE-476 | 12 | 6 | 18 |
| c | path-traversal | CWE-22 | 12 | 5 | 17 |
| c | use-after-free | CWE-416 | 12 | 5 | 17 |
| cpp | buffer-overflow | CWE-787 | 13 | 5 | 18 |
| cpp | command-injection | CWE-78 | 12 | 5 | 17 |
| cpp | double-free | CWE-415 | 12 | 6 | 18 |
| cpp | format-string | CWE-134 | 12 | 6 | 18 |
| cpp | integer-overflow | CWE-190 | 12 | 5 | 17 |
| cpp | iterator-invalidation | CWE-416 | 13 | 5 | 18 |
| cpp | missing-authz | CWE-862 | 12 | 5 | 17 |
| cpp | path-traversal | CWE-22 | 12 | 5 | 17 |
| javascript | command-injection | CWE-78 | 12 | 5 | 17 |
| javascript | eval-injection | CWE-95 | 12 | 5 | 17 |
| javascript | idor | CWE-639 | 12 | 5 | 17 |
| javascript | jwt-misuse | CWE-347 | 12 | 5 | 17 |
| javascript | nosql-injection | CWE-943 | 12 | 6 | 18 |
| javascript | prototype-pollution | CWE-1321 | 13 | 5 | 18 |
| javascript | ssrf | CWE-918 | 12 | 6 | 18 |
| javascript | xss | CWE-79 | 13 | 5 | 18 |
| python | command-injection | CWE-78 | 13 | 5 | 18 |
| python | hardcoded-secrets | CWE-798 | 12 | 5 | 17 |
| python | path-traversal | CWE-22 | 12 | 5 | 17 |
| python | pickle-deserialization | CWE-502 | 12 | 6 | 18 |
| python | sql-injection | CWE-89 | 13 | 5 | 18 |
| python | ssrf | CWE-918 | 12 | 6 | 18 |
| python | ssti | CWE-94 | 12 | 5 | 17 |
| python | yaml-unsafe-load | CWE-502 | 12 | 5 | 17 |
| rust | command-injection | CWE-78 | 12 | 6 | 18 |
| rust | hardcoded-secrets | CWE-798 | 12 | 5 | 17 |
| rust | integer-overflow-unsafe | CWE-190 | 12 | 5 | 17 |
| rust | path-traversal | CWE-22 | 12 | 5 | 17 |
| rust | sql-injection | CWE-89 | 12 | 6 | 18 |
| rust | ssrf | CWE-918 | 12 | 5 | 17 |
| rust | unsafe-misuse | CWE-787 | 13 | 5 | 18 |
| rust | unwrap-panic | CWE-754 | 13 | 5 | 18 |
| typescript | hardcoded-secrets | CWE-798 | 12 | 5 | 17 |
| typescript | jwt-misuse | CWE-347 | 12 | 5 | 17 |
| typescript | path-traversal | CWE-22 | 12 | 5 | 17 |
| typescript | prototype-pollution | CWE-1321 | 13 | 5 | 18 |
| typescript | sql-injection | CWE-89 | 12 | 6 | 18 |
| typescript | ssrf | CWE-918 | 12 | 6 | 18 |
| typescript | type-assertion-bypass | CWE-20 | 12 | 5 | 17 |
| typescript | xss | CWE-79 | 13 | 5 | 18 |

## Harness fields

Each case in `eval/benchmark-multilang.json`:

- `id` — deterministic (`{lang}-{category}-vuln|safe-{variant}`)
- `language`, `category`, `cwe` — metadata for analysis
- `file_path`, `diff` — unified diff hunks (10–80 lines typical)
- `expected` — harness categories: `injection`, `authz`, `secrets`, `crypto`, `config`, `dependency`, `other`
- `negative` — `true` when the diff is safe (no finding expected)

## Regenerate

```bash
npx tsx scripts/benchmarks/generate-multilang-corpus.ts
CASES_PER_LANG=167 npx tsx scripts/benchmarks/generate-multilang-corpus.ts  # ~1002 total
```

## Run evaluation

```bash
# Full multilang corpus (default path via env)
BENCHMARK_PATH=eval/benchmark-multilang.json npx tsx scripts/eval-models.ts

# Smoke (10 cases)
CASE_LIMIT=10 BENCHMARK_PATH=eval/benchmark-multilang.json npx tsx scripts/eval-models.ts

# Combined with legacy 18-case set
BENCHMARK_MODE=combined npx tsx scripts/eval-models.ts
```

See also `docs/OFFICIAL_EVAL_BENCHMARKS.md` and `docs/MODEL_EVAL.md`.

