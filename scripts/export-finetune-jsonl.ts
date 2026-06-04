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

const REF_DIR = join(REPO_ROOT, "eval", "reference-database");
const CORPUS = join(REF_DIR, "corpus-v1.json");
const OUT = join(REF_DIR, "finetune-train.jsonl");

const SYSTEM = `You are a security-focused code reviewer.
Analyze the pull request diff for vulnerabilities (injection, authz, secrets, crypto, unsafe dependencies).
Respond with a JSON array only. Each item: { "severity", "category", "title", "detail", "file_path", "line_start" }.
severity: info|low|medium|high|critical. category: injection|authz|secrets|crypto|dependency|config|other.
If no issues, return [].`;

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

function labelFindings(c: ReferenceCase): string {
  if (c.negative || c.expected.length === 0) return "[]";
  const findings = c.expected.map((e, i) => ({
    severity: "high",
    category: e.category,
    title: `${c.cwe ?? c.category} pattern`,
    detail: `Expected ${e.category} finding for benchmark case ${c.ref_id}`,
    file_path: c.file_path,
    line_start: 1 + i,
  }));
  return JSON.stringify(findings);
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
      { role: "system", content: SYSTEM },
      { role: "user", content: user },
      { role: "assistant", content: labelFindings(c) },
    ],
    metadata: {
      ref_id: c.ref_id,
      split: c.split,
      source: c.source,
      negative: c.negative,
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
