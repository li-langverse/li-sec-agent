/**
 * Build canonical reference benchmark corpus v1 from existing + imported sources.
 *
 * Usage:
 *   npx tsx scripts/benchmarks/build-reference-db.ts
 *   CHUNK_MB=4 npx tsx scripts/benchmarks/build-reference-db.ts
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "./cwe-shared.js";
import type { BenchmarkCase } from "./generate-multilang-corpus.js";
import {
  contentHash,
  toReferenceCase,
  type ProvenanceSource,
  type ReferenceCase,
} from "./reference-db-types.js";

const REF_DIR = join(REPO_ROOT, "eval", "reference-database");
const MULTILANG = join(REPO_ROOT, "eval", "benchmark-multilang.json");
const CWE_EXPANDED = join(REPO_ROOT, "eval", "benchmark-cwe-expanded.json");
const OSSF_SUBSET = join(REF_DIR, "ossf-subset.json");
const SYNTHETIC_EXPANDED = join(REF_DIR, "synthetic-expanded.json");

type SourceInput = {
  path: string;
  source: ProvenanceSource;
  license: string;
};

function loadCases(path: string): BenchmarkCase[] {
  if (!existsSync(path)) return [];
  return JSON.parse(readFileSync(path, "utf8")) as BenchmarkCase[];
}

function ingest(
  cases: BenchmarkCase[],
  source: ProvenanceSource,
  license: string,
  byHash: Map<string, ReferenceCase>,
  stats: { skipped_dup: number }
): void {
  for (const c of cases) {
    const hash = contentHash(c);
    if (byHash.has(hash)) {
      stats.skipped_dup++;
      continue;
    }
    const ref = toReferenceCase(c, source, { license });
    byHash.set(hash, ref);
  }
}

function buildStats(cases: ReferenceCase[]) {
  const byLang: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  const bySplit: Record<string, number> = {};
  const byCat: Record<string, number> = {};
  const cwes = new Set<string>();
  for (const c of cases) {
    byLang[c.language] = (byLang[c.language] ?? 0) + 1;
    bySource[c.source] = (bySource[c.source] ?? 0) + 1;
    bySplit[c.split] = (bySplit[c.split] ?? 0) + 1;
    byCat[c.harness_category] = (byCat[c.harness_category] ?? 0) + 1;
    if (c.cwe) cwes.add(c.cwe);
  }
  return {
    total_cases: cases.length,
    positive_cases: cases.filter((c) => !c.negative).length,
    negative_cases: cases.filter((c) => c.negative).length,
    unique_cwes: cwes.size,
    unique_content_hashes: cases.length,
    by_language: byLang,
    by_source: bySource,
    by_split: bySplit,
    by_harness_category: byCat,
  };
}

function writeCorpus(cases: ReferenceCase[], chunkMb: number): string[] {
  const json = JSON.stringify(cases, null, 2);
  const bytes = Buffer.byteLength(json, "utf8");
  const maxBytes = chunkMb * 1024 * 1024;

  if (bytes <= maxBytes) {
    const out = join(REF_DIR, "corpus-v1.json");
    writeFileSync(out, json + "\n", "utf8");
    console.log(`Wrote ${out} (${(bytes / 1024 / 1024).toFixed(2)} MB, ${cases.length} cases)`);
    return ["corpus-v1.json"];
  }

  const perChunk = Math.ceil(cases.length / Math.ceil(bytes / maxBytes));
  const files: string[] = [];
  for (let i = 0; i < cases.length; i += perChunk) {
    const part = cases.slice(i, i + perChunk);
    const name = `corpus-v1-part-${String(files.length + 1).padStart(2, "0")}.json`;
    writeFileSync(join(REF_DIR, name), JSON.stringify(part, null, 2) + "\n", "utf8");
    files.push(name);
    console.log(`Wrote ${name} (${part.length} cases)`);
  }
  return files;
}

function main(): void {
  mkdirSync(REF_DIR, { recursive: true });
  const chunkMb = Number(process.env.CHUNK_MB ?? "8");

  const inputs: SourceInput[] = [
    { path: MULTILANG, source: "multilang-synthetic", license: "MIT (li-sec-agent)" },
    { path: CWE_EXPANDED, source: "cwe-expanded-synthetic", license: "MIT (li-sec-agent)" },
    { path: SYNTHETIC_EXPANDED, source: "reference-expanded-synthetic", license: "MIT (li-sec-agent)" },
    { path: OSSF_SUBSET, source: "ossf-cve-benchmark", license: "MIT (OSSF metadata); per-repo OSS for snippets" },
  ];

  const byHash = new Map<string, ReferenceCase>();
  const dup = { skipped_dup: 0 };
  const sourceCounts: Array<{ id: string; path: string; license: string; count: number; notes?: string }> = [];

  for (const inp of inputs) {
    const raw = loadCases(inp.path);
    const before = byHash.size;
    ingest(raw, inp.source, inp.license, byHash, dup);
    const added = byHash.size - before;
    sourceCounts.push({
      id: inp.source,
      path: inp.path.replace(REPO_ROOT, "").replace(/^[/\\]/, "").replace(/\\/g, "/"),
      license: inp.license,
      count: added,
      notes: !existsSync(inp.path) ? "file missing — skipped" : undefined,
    });
    console.log(`${inp.source}: +${added} (${raw.length} raw, ${dup.skipped_dup} dupes total)`);
  }

  const cases = [...byHash.values()].sort((a, b) => a.ref_id.localeCompare(b.ref_id));
  const corpusFiles = writeCorpus(cases, chunkMb);

  const manifest = {
    schema_version: 1,
    corpus_version: "v1",
    generated_at: new Date().toISOString(),
    corpus_files: corpusFiles,
    sources: sourceCounts,
    stats: buildStats(cases),
    splits: {
      train_pct: 70,
      eval_pct: 20,
      holdout_pct: 10,
      assignment: "sha256(ref_id)[0] mod 100 → 0-69 train, 70-89 eval, 90-99 holdout",
    },
    licensing: {
      "multilang-synthetic": "MIT — li-sec-agent generated",
      "cwe-expanded-synthetic": "MIT — li-sec-agent generated",
      "reference-expanded-synthetic": "MIT — li-sec-agent generated",
      "ossf-cve-benchmark": "MIT metadata; upstream repo licenses apply to code excerpts",
      "ported-ossf": "MIT port templates; attribute CVE + original repo",
      mitre_cwe: "MITRE CWE reference data — taxonomy ids only",
      owasp_benchmark: "GPL-2.0 — metadata only, no Java copied",
    },
    roadmap: {
      target_cases_v2: 2500,
      target_cases_v3: 10000,
    },
    dedupe: {
      strategy: "content_hash = sha256(file_path + diff)[0:16]",
      skipped_duplicates: dup.skipped_dup,
    },
    content_digest: createHash("sha256").update(JSON.stringify(cases.map((c) => c.ref_id))).digest("hex").slice(0, 16),
  };

  writeFileSync(join(REF_DIR, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", "utf8");
  console.log(`\nReference corpus v1: ${cases.length} cases`);
  console.log(`  Sources: ${JSON.stringify(manifest.stats.by_source)}`);
  console.log(`  Splits: ${JSON.stringify(manifest.stats.by_split)}`);
  console.log(`Manifest: eval/reference-database/manifest.json`);
}

main();
