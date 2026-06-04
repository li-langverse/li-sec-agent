/**
 * Reference security benchmark database — shared types and utilities.
 */

import { createHash } from "node:crypto";
import type { BenchmarkCase } from "./generate-multilang-corpus.js";
import { primaryHarnessCategory } from "./cwe-shared.js";

export type CorpusSplit = "train" | "eval" | "holdout";

export type ProvenanceSource =
  | "multilang-synthetic"
  | "cwe-expanded-synthetic"
  | "reference-expanded-synthetic"
  | "ossf-cve-benchmark"
  | "ported-ossf"
  | "juliet-sample"
  | "cyberseceval-adapted";

export type ReferenceCase = BenchmarkCase & {
  /** Stable id: ref-{sourceSlug}-{legacyId} */
  ref_id: string;
  source: ProvenanceSource;
  provenance: {
    source: ProvenanceSource;
    upstream_id?: string;
    cve?: string;
    cwe?: string;
    repository?: string;
    license?: string;
    notes?: string;
  };
  split: CorpusSplit;
  difficulty: "easy" | "medium" | "hard";
  content_hash: string;
  harness_category: string;
};

export function contentHash(c: Pick<BenchmarkCase, "diff" | "file_path">): string {
  return createHash("sha256")
    .update(`${c.file_path}\n${c.diff}`)
    .digest("hex")
    .slice(0, 16);
}

export function assignSplit(seed: string): CorpusSplit {
  const h = createHash("sha256").update(seed).digest();
  const bucket = h[0]! % 100;
  if (bucket < 70) return "train";
  if (bucket < 90) return "eval";
  return "holdout";
}

export function inferDifficulty(c: BenchmarkCase): ReferenceCase["difficulty"] {
  const lines = c.diff.split("\n").length;
  if (c.negative) return "easy";
  if (lines > 25 || c.diff.length > 1200) return "hard";
  if (lines > 14) return "medium";
  return "easy";
}

export function sourceSlug(source: ProvenanceSource): string {
  return source.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "");
}

export function toReferenceCase(
  c: BenchmarkCase,
  source: ProvenanceSource,
  extra?: Partial<ReferenceCase["provenance"]>
): ReferenceCase {
  const ref_id = `ref-${sourceSlug(source)}-${c.id}`;
  const harness_category = primaryHarnessCategory(c.cwe ?? "");
  return {
    ...c,
    ref_id,
    source,
    provenance: {
      source,
      upstream_id: c.id,
      cwe: c.cwe,
      ...extra,
    },
    split: assignSplit(ref_id),
    difficulty: inferDifficulty(c),
    content_hash: contentHash(c),
    harness_category,
  };
}

export function toHarnessCase(c: ReferenceCase): BenchmarkCase {
  const { ref_id: _r, source: _s, provenance: _p, split: _sp, difficulty: _d, content_hash: _h, harness_category: _hc, ...base } = c;
  return base;
}
