# Official security evaluation benchmarks (research)

Research for replacing or augmenting `eval/benchmark-cases.json` (18 synthetic PR diffs) with **widely cited, real-world** cases suitable for **security-focused PR / diff review** and Ollama-based `scripts/eval-models.ts`.

**Target harness shape** (unchanged):

```json
{
  "id": "cve-2019-xxxx-file",
  "file_path": "relative/path.ts",
  "diff": "unified diff hunk(s)",
  "expected": [{ "category": "injection" }],
  "negative": false
}
```

Categories must map to production scanner buckets: `injection`, `authz`, `secrets`, `crypto`, `config`, `dependency`, `other`.

---

## Comparison table (viable benchmarks)

| Benchmark | Official source | License | Scale | Format | Real CVE? | Toughness | Diff-in-prompt (Ollama) | Integration effort | Fit for li-sec-agent PR review |
|-----------|---------------|---------|-------|--------|-----------|-----------|-------------------------|-------------------|------------------------------|
| **OpenSSF CVE Benchmark** | [ossf-cve-benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark), [OpenSSF blog](https://openssf.org/blog/2020/12/09/introducing-the-openssf-cve-benchmark/) | **MIT** (tooling + metadata) | **218+** JS/TS CVEs | Vuln commit + patch commit per CVE; weakness line metadata | **Yes** (NVD-linked) | High for SAST; subtle real bugs | **Yes** — `git diff vuln..patch` per file | **Low–medium**: clone CVE repos or use metadata; map CWE→category | **Best primary** — designed for “did the tool see the CVE?” on real code |
| **PrimeVul** (paired test) | [DLVulDet/PrimeVul](https://github.com/DLVulDet/PrimeVul), [arXiv:2403.18624](https://arxiv.org/abs/2403.18624) | **MIT** (dataset repo) | ~7k vuln + 229k benign functions; **paired test** is hard subset | Function before/after (patch pair); optional commit metadata | **Yes** (de-duplicated, chronological split) | **Very high** — SOTA LLMs ≈ random on pairs | **Partial** — use commit diff if commit SHAs present; else function-level prompt | **Medium**: download JSONL; subset 50–200 pairs; C/C++ heavy | **Best secondary** — stress-test recall on subtle real fixes |
| **JitVul** | [ACL 2025](https://aclanthology.org/2025.acl-long.1490/) (built from PrimeVul) | Follows upstream / paper artifact | **879 CVEs**, **1,758** commit pairs, 91 CWEs | Introducing + fixing commits per function | **Yes** | **Very high** — JIT + interprocedural context | **Yes** — commit-level diffs | **Medium–high**: reproduce dataset build or use released splits | **Strong** — closest to “PR introduced vuln” workflow |
| **CVEfixes** | [secureIT-project/CVEfixes](https://github.com/secureIT-project/CVEfixes), [Zenodo v1.0.8](https://zenodo.org/records/13118970), [PROMISE ’21 paper](https://dl.acm.org/doi/10.1145/3475960.3475985) | **CC BY 4.0** (data); MIT (collector) | **11,873 CVEs**, 12k+ fix commits, multi-language | SQL DB: `file_change`, before/after source, method level | **Yes** | High at scale; noisy labels if used naïvely | **Yes** — `diff` from `code_before`/`code_after` | **Medium**: Zenodo download + SQLite ETL script | **Good** for large curated subset; watch **OSS license** per repo |
| **CWE-Bench-Java** | [iris-sast/cwe-bench-java](https://github.com/iris-sast/cwe-bench-java), [arXiv:2405.17238](https://arxiv.org/abs/2405.17238) | Check repo (academic; no explicit commercial note in README) | **120** CVEs, 4 CWE families | Full repo checkout + fix locations | **Yes** (manually vetted) | High quality, narrow CWE coverage | **Partial** — extract hunks from fix commits | **High**: Linux build scripts, Java-only | **Moderate** — excellent ground truth, wrong language for many PRs |
| **OpenSSF-style: eyeballvul** | [timothee-chauvin/eyeballvul](https://github.com/timothee-chauvin/eyeballvul), [arXiv:2407.08708](https://arxiv.org/abs/2407.08708) | **MIT** | **24k+** vulns, 6k+ revisions (~55 GB) | Whole revision + OSV ground truth | **Yes** | High; **future-proof** (weekly OSV) | **Poor** for 12 GB Ollama — full-repo, not diff | **High** cost; subset by commit hash prefix | **Poor** for current harness; consider later for “full repo” mode |
| **CyberSecEval** (Meta) | [meta-llama/PurpleLlama/CybersecurityBenchmarks](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks), [paper](https://arxiv.org/html/2312.04724) | **MIT** | Hundreds–thousands (auto-generated insecure-code prompts) | Autocomplete / instruct **prompts**, not PR diffs | Mixed (ICD on OSS snippets) | Moderate for **generation** risk, not review | **No** — different task | **Low** to run upstream; **low mapping** value | **Poor** for PR review; use for insecure-codegen regression only |
| **AutoPatchBench** (CyberSecEval 4) | [PurpleLlama](https://github.com/meta-llama/PurpleLlama), [Meta engineering post](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/) | MIT + third-party bits | **136** (lite **120**) C/C++ fuzz crashes | Agent patch + fuzz verify | Real fuzz findings | High for **repair**, not detection | **No** | **Very high** (TB storage for full set) | **Poor** for diff review |
| **SEC-bench** | [SEC-bench/SEC-bench](https://github.com/SEC-bench/SEC-bench), NeurIPS 2025 | Check repo | Auto-built CVE instances | Docker agents: PoC + patch | **Yes** | **Very high** (≤34% patch success) | **No** — agent/container task | **Very high** | **Different product surface** (agents, not static PR scan) |
| **CVE-Bench** | [WhileBug/CVEBench](https://github.com/WhileBug/CVEBench), NAACL 2025 | Check repo | **509** CVEs, 4 languages | Full env + exploit tests | **Yes** | High (repair) | **No** | **Very high** | Repair benchmark, not PR review |
| **VulnBench** | [vulnbench/vulnbench](https://github.com/vulnbench/vulnbench), [site](https://vulnbench.ghostsecurity.com/) | Open source (see repo) | **1,650** / curated **200** | Patch generation + LLM judge | **Yes** (GitHub Advisory) | **Very high** (best ~22.5% fix on 200) | **No** (patch task) | **Medium** | Repair / patch quality, not diff detection |
| **VulDetectBench** | [Sweetaroo/VulDetectBench](https://github.com/Sweetaroo/VulDetectBench) | Academic | 500+ per task tier | Q&A: existence, CWE, root cause, lines | Curated snippets | Progressive difficulty | **Partial** (snippets, not unified diff) | **Low–medium** | Useful for **category/CWE** calibration, not full PR diff |
| **VulBench** (Hustcw) | [Hustcw/VulBench](https://github.com/Hustcw/VulBench), [arXiv:2311.12420](https://arxiv.org/abs/2311.12420) | **MIT** | Multi-dataset (CTF, MAGMA, Devign, D2A, Big-Vul) | Function classification | Mixed CTF + CVE-derived | Moderate; known dataset leakage issues | Function text in prompt | **Medium** | ML classification, not PR-shaped |
| **OpenSSF CVE Benchmark (alt name)** | Same as row 1 | MIT | 218+ | Commits | Yes | High | Yes | Low–medium | **Primary** |
| **ossf-cve-benchmark** | Same | MIT | 200+ JS/TS | Repo snapshots | Yes | High | Yes | Low–medium | **Primary** |
| **DiverseVul / Big-Vul / Devign** | [wagner-group/diversevul](https://github.com/wagner-group/diversevul), papers | **CC BY 4.0** (DiverseVul paper); data via Google Drive | 10k–300k+ **functions** | Function-level labels | CVE-derived but **weak labels** | Inflates metrics; **PrimeVul** explicitly debunks | Full function, not diff | **Medium** | **Not recommended** alone for tough PR eval |
| **OWASP Benchmark** | [OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) | **GPL-2.0** | Thousands of **synthetic** test cases | Runnable vulnerable web app | **Synthetic** | Good for SAST vendors; not realistic PRs | Full file / app scan | **Medium** | **Poor** for real CVE PR review; GPL friction |
| **OWASP Juice Shop** | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | MIT (app) | CTF-style app | Running app + challenges | Intentionally vulnerable | Training, not benchmark labels | No | N/A | **Not applicable** |
| **SWE-bench** | [SWE-bench/SWE-bench](https://github.com/SWE-bench/SWE-bench) | Apache-2.0 | 2.3k issues (500 Verified) | Issue + repo + test oracle | **General bugs**, not security-focused | N/A for security | Issue-level patch | **High** | **No dedicated security subset**; use CVE-Bench / VulnBench instead |
| **Semgrep / CodeQL “eval”** | Vendor rules + community | Tool-specific | No single official **labeled TP/FP** set for LLM PR review | Rule alerts on code | N/A | Varies | N/A | Use **OpenSSF** or **CWE-Bench-Java** papers for SAST baselines | Complements, not replacement dataset |
| **microsoft/cyberseceval** | Redirects to **Meta PurpleLlama** | MIT | See CyberSecEval | Prompts | Mixed | See above | No | Low | Poor fit for PR diff |
| **google/security-benchmarks** | **No public repo** at `google/security-benchmarks` (404) | — | — | — | — | — | — | — | **Not available**; use **eyeballvul** / **OSS-Fuzz→AutoPatchBench** instead |
| **SecVulEval** | [arXiv:2505.19828](https://arxiv.org/html/2505.19828) | Academic | **5,867 CVEs**, statement-level | Function + line labels | **Yes** | **Very high** (best F1 ~24% statement-level) | Function + context | **Medium** | Strong research set; map CWE→category |
| **Real-Vuln-Benchmark** | [kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) | Check repo | Growing real-app ground truth | Scanner-oriented (F3 score) | **Yes** | High realism | File + line, not always minimal diff | **Medium** | Good for **scanner** leaderboard; adapt for diff subset |
| **ReVeal / LineVul / FormAI** | Various papers | Academic | Variable | Function / line | Mixed | Research use | Partial | High | Secondary sources only |
| **HumanEval security** | No standard official extension | — | — | — | — | — | — | — | **Not applicable** |

**Note on “HELO”:** In security-ML literature this often meant **SEC-bench** (NeurIPS 2025) or was confused with unrelated **HELO Cryptography** (IoT). There is no widely cited “HELO” vulnerability-detection benchmark.

---

## Non-viable or poor-fit (short rationale)

| Name | Why skip for li-sec-agent PR diff eval |
|------|--------------------------------------|
| Big-Vul / DiverseVul / Devign alone | Function-level, label noise, data leakage; superseded by **PrimeVul** for honest LLM eval |
| OWASP Benchmark | Synthetic Java web app; GPL; measures SAST on toy app, not real PR diffs |
| Juice Shop | Training CTF, not labeled diff benchmark |
| CyberSecEval / microsoft path | Insecure **generation** and red-team; not “review this PR diff” |
| SWE-bench | General bugfix; no security subset |
| SEC-bench / CVE-Bench / VulnBench | Agent repair + Docker + exploits; wrong task unless product becomes patch bots |
| eyeballvul (full) | Repo-scale, expensive; use subsets only if expanding beyond diff harness |
| google/security-benchmarks | Repository not found |

---

## Recommended adoption (top 2)

### 1. Primary: **OpenSSF CVE Benchmark** (MIT)

**Why:** Official OpenSSF / Black Hat–launched standard for evaluating security tools on **real JS/TS CVEs** with **vulnerable vs patched commits** — structurally the same question as li-sec-agent (“did we flag the regression?”). Aligns with PR diff review after extracting per-CWE hunks.

**Suggested subset:** Start **50–100 CVEs** stratified by CWE (XSS, path traversal, prototype pollution, etc.), balanced **positive / negative** using **patched commits as negatives** (expect `[]` findings).

**License:** MIT for benchmark metadata and tooling; underlying project code remains subject to each OSS license (same as scanning customer repos).

### 2. Secondary: **PrimeVul paired test split** (MIT) or **JitVul** commit pairs

**Why:** Most **honest** “tough” LLM benchmark in 2024–2025 literature; paired vulnerable vs patched functions/commits expose overfitting on Big-Vul-style sets. Use **50–150 pairs** where commit metadata allows unified diffs.

**License:** MIT for PrimeVul repository; training/evaluation on extracted code still subject to per-project OSS licenses.

Keep **synthetic 18-case** `benchmark-cases.json` as a **fast smoke** suite (CI, regression on category mapping), not as the only “official” score.

---

## Proposed integration plan

### Phase 0 — Schema (no change)

`scripts/eval-models.ts` already expects `BenchmarkCase` with `diff`, `expected`, `negative`. Add optional fields for traceability:

```json
{
  "id": "ossf-CVE-2020-11022-acme-widget",
  "source": "ossf-cve-benchmark",
  "cve": "CVE-2020-11022",
  "cwe": "CWE-79",
  "file_path": "lib/widget.js",
  "diff": "...",
  "expected": [{ "category": "injection" }],
  "negative": false
}
```

### Phase 1 — OpenSSF subset (~2–3 days)

1. Add `scripts/benchmarks/fetch-ossf-cve-subset.ts`:
   - Clone or shallow-fetch `ossf-cve-benchmark/CVEs` metadata.
   - For each selected CVE: `git diff <vuln_commit> <patch_commit> -- <weakness_file>`.
   - Map CWE → li-sec-agent category (table in script).
   - Emit `eval/benchmark-ossf.json` (50–100 cases).
2. Extend `eval-models.ts` to accept `BENCHMARK_PATH=eval/benchmark-ossf.json` or merge arrays.
3. Document run in `docs/MODEL_EVAL.md`.

### Phase 2 — PrimeVul / JitVul hard pairs (~3–5 days)

1. Download `primevul_test_paired.jsonl` from [Hugging Face mirror](https://huggingface.co/datasets/colin/PrimeVul) or [DLVulDet/PrimeVul](https://github.com/DLVulDet/PrimeVul).
2. Filter: C/C++/JS with `commit_link` / hash; cap diff size (e.g. ≤8k tokens for 12 GB Ollama).
3. Positives: vulnerable-side diff; negatives: patched-side or benign pair member (`negative: true`).
4. Emit `eval/benchmark-primevul-paired.json` (50–150 cases).

### Phase 3 — Scoring enhancements (optional)

- Match on **CWE family** or file path, not only coarse `category`.
- Track **negative pass rate** separately for patched commits (critical for PR noise).

### Phase 4 — CI policy

| Suite | Cases | When |
|-------|-------|------|
| `benchmark-cases.json` | 18 synthetic | Every PR / fast smoke |
| `benchmark-ossf.json` | 50–100 real CVE diffs | Weekly / release |
| `benchmark-primevul-paired.json` | 50–150 hard pairs | Monthly / model change |

---

## CWE → category mapping (starter)

| CWE families | `category` |
|--------------|------------|
| 79, 80, 83, 87, 89, 90, 94, 917 | `injection` |
| 22, 23, 36, 73 | `injection` (path) |
| 798, 259, 321, 798 | `secrets` |
| 327, 328, 330, 759, 916 | `crypto` |
| 862, 863, 287, 306, 639 | `authz` |
| 16, 1188, 942, 1021 | `config` |
| Other | `other` |

---

## License summary (commercial use)

| Asset | Commercial use |
|-------|----------------|
| OpenSSF CVE Benchmark metadata/tooling | **MIT** — OK |
| PrimeVul tooling/dataset repo | **MIT** — OK |
| CVEfixes database | **CC BY 4.0** — OK with attribution |
| DiverseVul paper/data | **CC BY 4.0** — OK with attribution |
| OWASP Benchmark | **GPL-2.0** — avoid embedding code in proprietary products; OK for eval-only checkout |
| CyberSecEval / PurpleLlama | **MIT** — OK |
| Extracted vulnerable **source code** from CVE repos | Subject to each project’s license (MIT/Apache/GPL/…); eval-only cloning is standard research practice; redistribution of snippets needs per-repo check |

---

## References

- Bhandari et al., CVEfixes, PROMISE 2021 — [DOI 10.1145/3475960.3475985](https://doi.org/10.1145/3475960.3475985)
- Ding et al., PrimeVul, 2024 — [arXiv:2403.18624](https://arxiv.org/abs/2403.18624)
- Bhatt et al., CyberSecEval, 2023 — [arXiv:2312.04724](https://arxiv.org/abs/2312.04724)
- Chauvin, eyeballvul, 2024 — [arXiv:2407.08708](https://arxiv.org/abs/2407.08708)
- Li et al., CWE-Bench-Java / IRIS, 2024 — [arXiv:2405.17238](https://arxiv.org/abs/2405.17238)
- Lee et al., SEC-bench, NeurIPS 2025 — [OpenReview](https://openreview.net/forum?id=HZDKrKT6Mt)
- JitVul, ACL 2025 — [ACL anthology](https://aclanthology.org/2025.acl-long.1490/)
- OpenSSF CVE Benchmark — [GitHub](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark)

---

*Last updated: 2026-06-03. No full 27B eval run performed.*
