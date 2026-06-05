/**
 * Export reference corpus to OpenAI-style messages JSONL for SFT fine-tuning.
 *
 * Usage:
 *   npx tsx scripts/export-finetune-jsonl.ts
 *   SPLIT=train npx tsx scripts/export-finetune-jsonl.ts
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "./benchmarks/cwe-shared.js";
import type { ReferenceCase } from "./benchmarks/reference-db-types.js";
import { SECURITY_REVIEWER_SYSTEM_PROMPT } from "../src/llm/security-prompt.js";

const REF_DIR = join(REPO_ROOT, "eval", "reference-database");
const CORPUS = join(REF_DIR, "corpus-v1.json");
const OUT = join(REF_DIR, "finetune-train.jsonl");
const MITIGATION_GOLDEN = join(REPO_ROOT, "eval", "mitigation-examples.json");

type GoldenMitigation = {
  finding: Record<string, unknown>;
  mitigation: Record<string, unknown>;
};

function loadGoldenMitigations(): GoldenMitigation[] {
  if (!existsSync(MITIGATION_GOLDEN)) return [];
  return JSON.parse(readFileSync(MITIGATION_GOLDEN, "utf8")) as GoldenMitigation[];
}

function mitigationForCategory(c: ReferenceCase): Record<string, unknown> {
  const golden = loadGoldenMitigations();
  const cwe = c.cwe ?? "";
  const match =
    golden.find((g) => g.finding.cwe_id === cwe) ??
    golden.find((g) => g.finding.category === c.harness_category);
  if (match) {
    return {
      ...match.mitigation,
      title: match.mitigation.title,
      description: `Remediate ${c.cwe ?? c.category} in ${c.file_path}. ${match.mitigation.description}`,
    };
  }
  return {
    title: `Remediate ${c.cwe ?? c.category}`,
    description: `Apply secure coding practices for ${c.harness_category} in this diff.`,
    effort: "medium",
    references: c.cwe
      ? [`https://cwe.mitre.org/data/definitions/${c.cwe.replace(/^CWE-/, "")}.html`]
      : [],
    alternative_approaches: [],
  };
}

function loadCorpus(): ReferenceCase[] {
  if (!existsSync(CORPUS)) {
    const idx = join(REF_DIR, "manifest.json");
    if (existsSync(idx)) {
      const m = JSON.parse(readFileSync(idx, "utf8")) as { corpus_files?: string[] };
      const parts = (m.corpus_files ?? []).map((f) =>
        JSON.parse(readFileSync(join(REF_DIR, f), "utf8")) as ReferenceCase[]
      );
      return parts.flat();
    }
    throw new Error("Run npm run benchmark:build-reference-db first");
  }
  return JSON.parse(readFileSync(CORPUS, "utf8")) as ReferenceCase[];
}

function labelScanOutput(c: ReferenceCase): string {
  if (c.negative || c.expected.length === 0) return "[]";
  const items = c.expected.map((e, i) => ({
    finding: {
      severity: "high",
      category: e.category,
      cwe_id: c.cwe ?? null,
      title: `${c.cwe ?? c.category} pattern`,
      detail: `Expected ${e.category} finding for benchmark case ${c.ref_id}`,
      file_path: c.file_path,
      line_range: { start: 1 + i },
      evidence: c.diff.split("\n").find((l) => l.startsWith("+")) ?? "",
      confidence: 0.85,
    },
    mitigation: mitigationForCategory(c),
  }));
  return JSON.stringify(items);
}

function toRecord(c: ReferenceCase): object {
  const user = [
    `File: ${c.file_path}`,
    `Language: ${c.language}`,
    c.cwe ? `CWE: ${c.cwe}` : "",
    "",
    "```diff",
    c.diff,
    "```",
  ]
    .filter(Boolean)
    .join("\n");

  return {
    messages: [
      { role: "system", content: SECURITY_REVIEWER_SYSTEM_PROMPT },
      { role: "user", content: user },
      { role: "assistant", content: labelScanOutput(c) },
    ],
    metadata: {
      ref_id: c.ref_id,
      split: c.split,
      source: c.source,
      negative: c.negative,
      has_mitigation: !c.negative && c.expected.length > 0,
    },
  };
}

async function main(): Promise<void> {
  const splitFilter = process.env.SPLIT;
  const cases = loadCorpus().filter((c) => !splitFilter || c.split === splitFilter);

  const lines = cases.map((c) => JSON.stringify(toRecord(c)));
  mkdirSync(REF_DIR, { recursive: true });
  writeFileSync(OUT, lines.join("\n") + (lines.length ? "\n" : ""), "utf8");
  console.log(`Wrote ${OUT}: ${lines.length} records (split=${splitFilter ?? "all"})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
