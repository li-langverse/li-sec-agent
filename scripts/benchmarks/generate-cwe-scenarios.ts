/**
 * CWE expansion scenario generator — P0 backlog first, 3–5 safe synthetic diffs per CWE.
 *
 * Usage:
 *   npx tsx scripts/benchmarks/generate-cwe-scenarios.ts
 *   TIER_FILTER=P0 npx tsx scripts/benchmarks/generate-cwe-scenarios.ts
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  REPO_ROOT,
  loadBacklog,
  normalizeLanguage,
  parseCweNumber,
  primaryHarnessCategory,
  type BacklogItem,
} from "./cwe-shared.js";
import { EXTRA_TEMPLATES, CWE_TEMPLATE_ALIAS } from "./cwe-extra-templates.js";
import {
  TEMPLATE_BY_LANG,
  buildCase,
  type BenchmarkCase,
  type CaseTemplate,
  type Language,
} from "./generate-multilang-corpus.js";

const ALL_TEMPLATES = [...EXTRA_TEMPLATES];

function slug(s: string): string {
  return s.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

function langExt(lang: Language): string {
  const map: Record<Language, string> = {
    c: "c",
    cpp: "cpp",
    rust: "rs",
    python: "py",
    javascript: "js",
    typescript: "ts",
  };
  return map[lang];
}

function poolForLang(lang: Language): CaseTemplate[] {
  return [...TEMPLATE_BY_LANG[lang], ...ALL_TEMPLATES.filter((t) => matchesLangExt(lang, t))];
}

function templatesFor(lang: Language, cweId: string): CaseTemplate[] {
  const pool = poolForLang(lang);
  const direct = pool.filter((t) => t.cwe === cweId);
  if (direct.length > 0) return direct;

  const alias = CWE_TEMPLATE_ALIAS[cweId];
  if (alias) {
    return pool
      .filter((t) => t.cwe === alias)
      .map((t) => ({ ...t, cwe: cweId, category: `${t.category}-as-${slug(cweId)}` }));
  }
  return [];
}

function matchesLangExt(lang: Language, t: CaseTemplate): boolean {
  const ext = langExt(lang);
  return t.ext === ext;
}

function makeCweCaseId(
  lang: Language,
  cweId: string,
  category: string,
  variant: number,
  negative: boolean
): string {
  const num = parseCweNumber(cweId);
  const prefix = negative ? "safe" : "vuln";
  return `${lang}-cwe-${num}-${slug(category)}-${prefix}-${String(variant).padStart(3, "0")}`;
}

function buildCweCase(
  lang: Language,
  tpl: CaseTemplate,
  cweId: string,
  variant: number,
  negative: boolean
): BenchmarkCase {
  const base = buildCase(lang, { ...tpl, cwe: cweId }, variant, negative);
  return {
    ...base,
    id: makeCweCaseId(lang, cweId, tpl.category, variant, negative),
    cwe: cweId,
    category: tpl.category,
  };
}

type ScenarioSlot = { lang: Language; tpl: CaseTemplate; variant: number };

function collectSlots(item: BacklogItem): ScenarioSlot[] {
  const slots: ScenarioSlot[] = [];
  const langs = item.languages
    .map(normalizeLanguage)
    .filter((l): l is Language => l !== undefined);

  for (const lang of langs) {
    const tpls = templatesFor(lang, item.cwe);
    for (let i = 0; i < tpls.length; i++) {
      slots.push({ lang, tpl: tpls[i]!, variant: i });
    }
  }
  return slots;
}

function generateForBacklogItem(item: BacklogItem, minScenarios: number): BenchmarkCase[] {
  const target = Math.max(minScenarios, Math.min(item.targetScenarios, 5));
  const slots = collectSlots(item);
  if (slots.length === 0) {
    console.warn(`No templates for ${item.cwe} — skipping`);
    return [];
  }

  const cases: BenchmarkCase[] = [];
  let v = 0;
  while (cases.filter((c) => !c.negative).length < target) {
    const slot = slots[v % slots.length]!;
    cases.push(buildCweCase(slot.lang, slot.tpl, item.cwe, slot.variant + Math.floor(v / slots.length), false));
    v++;
    if (v > target * 20) break;
  }

  const negTarget = Math.max(1, Math.floor(target / 4));
  let n = 0;
  while (cases.filter((c) => c.negative).length < negTarget && n < slots.length * 2) {
    const slot = slots[n % slots.length]!;
    cases.push(
      buildCweCase(slot.lang, slot.tpl, item.cwe, slot.variant + 100 + n, true)
    );
    n++;
  }

  return cases;
}

type CweDbScenario = {
  scenario_id: string;
  title: string;
  language: Language;
  category: string;
  diff: string;
  expected: BenchmarkCase["expected"];
  negative: boolean;
  cwe_id: string;
  source: "synthetic" | "ossf";
};

type CweDbEntry = {
  cwe_id: string;
  name: string;
  priority: string;
  languages: string[];
  scenarios: CweDbScenario[];
};

function toDbScenario(c: BenchmarkCase): CweDbScenario {
  return {
    scenario_id: c.id,
    title: c.category,
    language: c.language,
    category: primaryHarnessCategory(c.cwe ?? ""),
    diff: c.diff,
    expected: c.expected,
    negative: c.negative,
    cwe_id: c.cwe ?? "",
    source: "synthetic",
  };
}

function buildManifest(cases: BenchmarkCase[]) {
  const byCwe: Record<string, number> = {};
  const byLang: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const c of cases) {
    const cw = c.cwe ?? "unknown";
    byCwe[cw] = (byCwe[cw] ?? 0) + 1;
    byLang[c.language] = (byLang[c.language] ?? 0) + 1;
    const cat = primaryHarnessCategory(cw);
    byCategory[cat] = (byCategory[cat] ?? 0) + 1;
  }
  return {
    version: 1,
    generated_at: new Date().toISOString(),
    total_scenarios: cases.length,
    unique_cwes: Object.keys(byCwe).length,
    positive_scenarios: cases.filter((c) => !c.negative).length,
    negative_scenarios: cases.filter((c) => c.negative).length,
    by_cwe: byCwe,
    by_language: byLang,
    by_harness_category: byCategory,
    output_file: "eval/benchmark-cwe-expanded.json",
    database_file: "eval/cwe-database.json",
  };
}

function main(): void {
  const tierFilter = process.env.TIER_FILTER;
  const minScenarios = Number(process.env.MIN_SCENARIOS_PER_CWE ?? "3");
  let backlog = loadBacklog();
  if (tierFilter) {
    backlog = backlog.filter((b) => b.tier === tierFilter);
  }

  const taxonomyPath = join(REPO_ROOT, "eval", "cwe-taxonomy.json");
  let taxonomyNames = new Map<string, string>();
  try {
    const tax = JSON.parse(readFileSync(taxonomyPath, "utf8")) as {
      entries: Array<{ cwe_id: string; name: string }>;
    };
    taxonomyNames = new Map(tax.entries.map((e) => [e.cwe_id, e.name]));
  } catch {
    console.warn("eval/cwe-taxonomy.json not found — using backlog names");
  }

  const allCases: BenchmarkCase[] = [];
  const dbEntries: CweDbEntry[] = [];

  for (const item of backlog) {
    const cases = generateForBacklogItem(item, minScenarios);
    allCases.push(...cases);
    dbEntries.push({
      cwe_id: item.cwe,
      name: taxonomyNames.get(item.cwe) ?? item.name,
      priority: item.tier,
      languages: item.languages,
      scenarios: cases.map(toDbScenario),
    });
  }

  const seen = new Set<string>();
  for (const c of allCases) {
    if (seen.has(c.id)) throw new Error(`duplicate scenario id: ${c.id}`);
    seen.add(c.id);
  }

  const benchPath = join(REPO_ROOT, "eval", "benchmark-cwe-expanded.json");
  const samplePath = join(REPO_ROOT, "eval", "benchmark-cwe-expanded.sample.json");
  const dbPath = join(REPO_ROOT, "eval", "cwe-database.json");
  const manifestPath = join(REPO_ROOT, "eval", "cwe-database.manifest.json");

  const json = JSON.stringify(allCases, null, 2);
  writeFileSync(benchPath, json + "\n", "utf8");
  writeFileSync(samplePath, JSON.stringify(allCases.slice(0, 50), null, 2) + "\n", "utf8");

  const database = {
    version: 1,
    generated_at: new Date().toISOString(),
    cwe_entries: dbEntries.filter((e) => e.scenarios.length > 0),
  };
  writeFileSync(dbPath, JSON.stringify(database, null, 2) + "\n", "utf8");

  const manifest = buildManifest(allCases);
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");

  const sizeMb = Buffer.byteLength(json, "utf8") / (1024 * 1024);
  console.log(
    `Wrote ${allCases.length} scenarios, ${manifest.unique_cwes} CWEs -> ${benchPath} (${sizeMb.toFixed(2)} MB)`
  );
  console.log(`Wrote master DB -> ${dbPath}`);
  console.log(`Wrote manifest -> ${manifestPath}`);
}

main();
