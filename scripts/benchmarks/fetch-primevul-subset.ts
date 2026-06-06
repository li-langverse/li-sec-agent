/**
 * Fetch PrimeVul paired test subset and emit harness cases.
 * Source: HuggingFace mirror of DLVulDet/PrimeVul (MIT dataset repo).
 *
 * Usage:
 *   npx tsx scripts/benchmarks/fetch-primevul-subset.ts
 *   PRIMEVUL_LIMIT=50 npx tsx scripts/benchmarks/fetch-primevul-subset.ts
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { primaryHarnessCategory } from "./cwe-shared.js";
import { referenceDataDir } from "./reference-paths.js";
import type { BenchmarkCase, Language } from "./generate-multilang-corpus.js";

const PRIMEVUL_URL =
  "https://huggingface.co/datasets/colin/PrimeVul/resolve/main/primevul_test_paired.jsonl";
const REF_DIR = referenceDataDir();
const OUT_PATH = join(REF_DIR, "primevul-subset.json");

type PrimeVulRow = {
  idx?: number;
  func_name?: string;
  project?: string;
  commit_id?: string;
  file_name?: string;
  target?: number;
  cwe?: string[];
  func?: string;
  func_before?: string;
  func_after?: string;
};

function extToLang(project?: string, code?: string): Language {
  const p = (project ?? "").toLowerCase();
  if (p.includes("python") || (code ?? "").includes("def ")) return "python";
  if (p.includes("rust") || (code ?? "").includes("fn ")) return "rust";
  if (p.includes(".cpp") || p.includes("c++")) return "cpp";
  if (p.includes(".c") || p.includes("linux")) return "c";
  if (p.includes("typescript") || (code ?? "").includes(": string")) return "typescript";
  if (p.includes("javascript") || (code ?? "").includes("const ")) return "javascript";
  return "c";
}

function normalizeCwe(raw?: string[]): string {
  const id = raw?.[0] ?? "CWE-119";
  const n = id.replace(/^CWE-0*/, "");
  return `CWE-${n}`;
}

function toDiff(before: string, after: string, negative: boolean): string {
  const bLines = before.trim().split("\n").slice(0, 12);
  const aLines = after.trim().split("\n").slice(0, 12);
  const oldBlock = negative ? aLines : bLines;
  const newBlock = negative ? bLines : aLines;
  const body = oldBlock.map((l, i) => `-${l}`).concat(newBlock.map((l) => `+${l}`)).join("\n");
  return `@@ -1,${oldBlock.length} +1,${newBlock.length} @@\n${body}`.slice(0, 8000);
}

function buildCase(
  vuln: PrimeVulRow,
  fixed: PrimeVulRow,
  idx: number,
  negative: boolean
): BenchmarkCase | null {
  const before = (vuln.func ?? vuln.func_before)?.trim();
  const after = (fixed.func ?? fixed.func_after)?.trim();
  if (!before || !after || before === after) return null;

  const cwe = normalizeCwe(vuln.cwe);
  const lang = extToLang(vuln.project, before);
  const fn = vuln.file_name?.split("/").pop()?.replace(/\.\w+$/, "") ?? `fn_${idx}`;
  const file = vuln.file_name ?? `src/${(vuln.project ?? "unknown").replace(/\W+/g, "_")}/${fn}.${lang === "python" ? "py" : lang === "rust" ? "rs" : lang === "cpp" ? "cpp" : lang === "c" ? "c" : "js"}`;
  const suffix = negative ? "safe" : "vuln";
  const id = `primevul-${String(idx).padStart(4, "0")}-${suffix}`;

  return {
    id,
    language: lang,
    category: `primevul-${cwe.toLowerCase()}`,
    cwe,
    file_path: file,
    diff: toDiff(before, after, negative),
    expected: negative ? [] : [{ category: primaryHarnessCategory(cwe) }],
    negative,
  };
}

async function fetchJsonl(): Promise<PrimeVulRow[]> {
  const res = await fetch(PRIMEVUL_URL, { signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`PrimeVul fetch failed: ${res.status}`);
  const text = await res.text();
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l) as PrimeVulRow);
}

async function main(): Promise<void> {
  const limit = Number(process.env.PRIMEVUL_LIMIT ?? "50");
  mkdirSync(REF_DIR, { recursive: true });

  const cases: BenchmarkCase[] = [];
  const seen = new Set<string>();
  if (process.env.PRIMEVUL_APPEND === "1" && existsSync(OUT_PATH)) {
    const existing = JSON.parse(readFileSync(OUT_PATH, "utf8")) as BenchmarkCase[];
    for (const c of existing) {
      seen.add(`${c.file_path}:${c.diff.slice(0, 80)}`);
      cases.push(c);
    }
    console.log(`Append mode: loaded ${existing.length} existing PrimeVul cases`);
  }

  console.log(`Fetching PrimeVul paired test JSONL (limit ${limit})...`);
  const rows = await fetchJsonl();
  let added = 0;
  let pairIdx = 0;
  for (let i = 0; i + 1 < rows.length && pairIdx < limit; i += 2) {
    const vuln = rows[i]!;
    const fixed = rows[i + 1]!;
    if (vuln.target !== 1 || fixed.target !== 0) continue;
    const pos = buildCase(vuln, fixed, pairIdx, false);
    const neg = buildCase(vuln, fixed, pairIdx, true);
    for (const c of [pos, neg]) {
      if (!c) continue;
      const key = `${c.file_path}:${c.diff.slice(0, 80)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      cases.push(c);
      added++;
    }
    pairIdx++;
  }

  writeFileSync(OUT_PATH, JSON.stringify(cases, null, 2) + "\n", "utf8");
  console.log(
    `Wrote ${OUT_PATH}: ${cases.length} cases (+${added} new, ${cases.filter((c) => !c.negative).length} vuln pairs)`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
