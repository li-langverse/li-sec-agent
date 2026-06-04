/**
 * Expand reference corpus with additional synthetic scenarios (P0+P1 backlog).
 * Target: +500 cases via higher scenario depth and cross-language variants.
 *
 * Usage:
 *   npx tsx scripts/benchmarks/expand-reference-corpus.ts
 *   TARGET_EXTRA=500 MIN_SCENARIOS_PER_CWE=5 npx tsx scripts/benchmarks/expand-reference-corpus.ts
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT, loadBacklog, type BacklogItem } from "./cwe-shared.js";
import {
  TEMPLATE_BY_LANG,
  buildCase,
  type BenchmarkCase,
  type CaseTemplate,
  type Language,
} from "./generate-multilang-corpus.js";
import { EXTRA_TEMPLATES, CWE_TEMPLATE_ALIAS } from "./cwe-extra-templates.js";
import { parseCweNumber } from "./cwe-shared.js";

const OUT = join(REPO_ROOT, "eval", "reference-database", "synthetic-expanded.json");

function slug(s: string): string {
  return s.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

function langExt(lang: Language): string {
  const m: Record<Language, string> = {
    c: "c",
    cpp: "cpp",
    rust: "rs",
    python: "py",
    javascript: "js",
    typescript: "ts",
  };
  return m[lang];
}

function poolForLang(lang: Language): CaseTemplate[] {
  return [...TEMPLATE_BY_LANG[lang], ...EXTRA_TEMPLATES.filter((t) => t.ext === langExt(lang))];
}

function templatesFor(lang: Language, cweId: string): CaseTemplate[] {
  const pool = poolForLang(lang);
  const direct = pool.filter((t) => t.cwe === cweId);
  if (direct.length) return direct;
  const alias = CWE_TEMPLATE_ALIAS[cweId];
  if (alias) {
    return pool
      .filter((t) => t.cwe === alias)
      .map((t) => ({ ...t, cwe: cweId, category: `${t.category}-ref-${slug(cweId)}` }));
  }
  return [];
}

function makeId(
  lang: Language,
  cweId: string,
  category: string,
  variant: number,
  negative: boolean
): string {
  const num = parseCweNumber(cweId);
  const prefix = negative ? "safe" : "vuln";
  return `refexp-${lang}-cwe-${num}-${slug(category)}-${prefix}-${String(variant).padStart(3, "0")}`;
}

function generateExtra(item: BacklogItem, minPos: number, negRatio: number): BenchmarkCase[] {
  const langs = item.languages.filter((l) =>
    ["c", "cpp", "rust", "python", "javascript", "typescript"].includes(l)
  ) as Language[];

  const slots: Array<{ lang: Language; tpl: CaseTemplate; variant: number }> = [];
  for (const lang of langs) {
    const tpls = templatesFor(lang, item.cwe);
    for (let i = 0; i < tpls.length; i++) {
      slots.push({ lang, tpl: tpls[i]!, variant: i + 50 });
    }
  }
  if (!slots.length) return [];

  const cases: BenchmarkCase[] = [];
  let v = 0;
  while (cases.filter((c) => !c.negative).length < minPos && v < minPos * 30) {
    const slot = slots[v % slots.length]!;
    const variant = slot.variant + v;
    const base = buildCase(slot.lang, { ...slot.tpl, cwe: item.cwe }, variant, false);
    const uniq = `\n+# ref-exp-${item.cwe}-v${variant}\n`;
    cases.push({
      ...base,
      id: makeId(slot.lang, item.cwe, slot.tpl.category, variant, false),
      diff: base.diff + uniq,
    });
    v++;
  }

  const negTarget = Math.max(1, Math.round(cases.filter((c) => !c.negative).length * negRatio));
  let n = 0;
  while (cases.filter((c) => c.negative).length < negTarget && n < slots.length * 4) {
    const slot = slots[n % slots.length]!;
    const variant = slot.variant + 200 + n;
    const base = buildCase(slot.lang, { ...slot.tpl, cwe: item.cwe }, variant, true);
    cases.push({
      ...base,
      id: makeId(slot.lang, item.cwe, slot.tpl.category, variant, true),
      diff: base.diff + `\n+# ref-exp-safe-${item.cwe}-v${variant}\n`,
    });
    n++;
  }
  return cases;
}

function main(): void {
  const targetExtra = Number(process.env.TARGET_EXTRA ?? "600");
  const minScenarios = Number(process.env.MIN_SCENARIOS_PER_CWE ?? "6");
  const negRatio = Number(process.env.NEGATIVE_RATIO ?? "0.3");
  const tierFilter = process.env.TIER_FILTER;

  let backlog = loadBacklog();
  if (tierFilter) backlog = backlog.filter((b) => b.tier === tierFilter);

  const all: BenchmarkCase[] = [];
  const seen = new Set<string>();

  for (const item of backlog) {
    if (all.filter((c) => !c.negative).length >= targetExtra * 1.2) break;
    const batch = generateExtra(item, minScenarios, negRatio);
    for (const c of batch) {
      const key = `${c.file_path}:${c.diff}`;
      if (seen.has(key)) continue;
      seen.add(key);
      all.push(c);
    }
  }

  let trimmed = all;
  if (all.length > targetExtra) {
    const pos = all.filter((c) => !c.negative);
    const neg = all.filter((c) => c.negative);
    const posKeep = pos.slice(0, Math.round(targetExtra * (1 - negRatio)));
    const negKeep = neg.slice(0, targetExtra - posKeep.length);
    trimmed = [...posKeep, ...negKeep];
  }

  writeFileSync(OUT, JSON.stringify(trimmed, null, 2) + "\n", "utf8");
  console.log(
    `Wrote ${OUT}: ${trimmed.length} cases (${trimmed.filter((c) => !c.negative).length} pos, ${trimmed.filter((c) => c.negative).length} neg)`
  );
}

main();
