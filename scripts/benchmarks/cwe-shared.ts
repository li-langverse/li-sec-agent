/**
 * Shared CWE benchmark utilities — category mapping, backlog, MITRE fetch.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { HarnessCategory, Language } from "./generate-multilang-corpus.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(__dirname, "..", "..");

export const MITRE_REST_BASE = "https://cwe-api.mitre.org/api/v1/cwe/weakness";
export const DEFAULT_MIRROR = "https://cwe.klaut.pro";

export type BacklogItem = {
  cwe: string;
  name: string;
  tier: "P0" | "P1" | "P2";
  inBaseline: boolean;
  languages: string[];
  targetScenarios: number;
  note?: string;
};

export type BacklogFile = {
  version: number;
  generatedAt: string;
  items: BacklogItem[];
};

export type CweTaxonomyEntry = {
  id: number;
  cwe_id: string;
  name: string;
  description: string;
  abstraction: string;
  status: string;
  related_weaknesses: Array<{ nature: string; cwe_id: string }>;
  applicable_languages: string[];
  mapped_categories: HarnessCategory[];
  priority: "P0" | "P1" | "P2";
};

const LANG_ALIAS: Record<string, Language | undefined> = {
  c: "c",
  cpp: "cpp",
  rust: "rust",
  python: "python",
  javascript: "javascript",
  js: "javascript",
  typescript: "typescript",
  ts: "typescript",
};

export function normalizeLanguage(raw: string): Language | undefined {
  return LANG_ALIAS[raw.toLowerCase()];
}

export function parseCweNumber(cwe: string): number {
  const m = cwe.match(/(\d+)/);
  if (!m) throw new Error(`Invalid CWE id: ${cwe}`);
  return Number(m[1]);
}

export function loadBacklog(path = join(REPO_ROOT, "eval", "cwe-expansion-backlog.json")): BacklogItem[] {
  const data = JSON.parse(readFileSync(path, "utf8")) as BacklogFile;
  const seen = new Set<string>();
  const items: BacklogItem[] = [];
  for (const item of data.items) {
    if (seen.has(item.cwe)) continue;
    seen.add(item.cwe);
    items.push(item);
  }
  return items;
}

/** P0 tier + full backlog ids for MITRE enrich (50 CWEs). */
export function backlogCweIds(items: BacklogItem[]): string[] {
  return items.map((i) => i.cwe);
}

export function mapCweToHarnessCategories(cweId: string): HarnessCategory[] {
  const n = parseCweNumber(cweId);
  const injection = new Set([
    78, 79, 89, 94, 95, 119, 120, 121, 122, 125, 134, 190, 415, 416, 476, 502, 611, 776, 787, 918, 943,
    117, 1333, 1336,
  ]);
  const authz = new Set([287, 306, 352, 639, 862, 863]);
  const secrets = new Set([259, 532, 798]);
  const crypto = new Set([326, 327, 347]);
  const config = new Set([16, 209, 276, 400, 732, 770, 693, 704]);
  if (injection.has(n)) return ["injection"];
  if (authz.has(n)) return ["authz"];
  if (secrets.has(n)) return ["secrets"];
  if (crypto.has(n)) return ["crypto"];
  if (config.has(n)) return ["config"];
  if (n === 20) return ["injection", "other"];
  if (n === 434) return ["other"];
  if (n === 754) return ["other"];
  if (n === 829) return ["dependency"];
  if (n === 601) return ["injection"];
  return ["other"];
}

export function primaryHarnessCategory(cweId: string): HarnessCategory {
  return mapCweToHarnessCategories(cweId)[0] ?? "other";
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

type MitreWeakness = {
  ID: string;
  Name: string;
  Abstraction: string;
  Status: string;
  Description?: string;
  RelatedWeaknesses?: Array<{ Nature: string; CweID: string }>;
  ApplicablePlatforms?: Array<{ Type: string; Name?: string; Class?: string }>;
};

type MitreResponse = { Weaknesses?: MitreWeakness[] };

export async function fetchMitreWeakness(
  cweNum: number,
  delayMs = 350
): Promise<CweTaxonomyEntry | null> {
  const url = `${MITRE_REST_BASE}/${cweNum}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(45_000) });
  if (!res.ok) {
    console.warn(`MITRE ${cweNum}: HTTP ${res.status}`);
    return null;
  }
  const body = (await res.json()) as MitreResponse;
  const w = body.Weaknesses?.[0];
  if (!w) return null;

  const langs = new Set<string>();
  for (const p of w.ApplicablePlatforms ?? []) {
    if (p.Type === "Language" && p.Name) langs.add(p.Name.toLowerCase());
    if (p.Type === "Language" && p.Class === "Memory-Unsafe") {
      langs.add("c");
      langs.add("cpp");
    }
  }

  await sleep(delayMs);

  return {
    id: cweNum,
    cwe_id: `CWE-${cweNum}`,
    name: w.Name ?? `CWE-${cweNum}`,
    description: (w.Description ?? "").slice(0, 2000),
    abstraction: w.Abstraction ?? "",
    status: w.Status ?? "",
    related_weaknesses: (w.RelatedWeaknesses ?? []).map((r) => ({
      nature: r.Nature,
      cwe_id: `CWE-${r.CweID}`,
    })),
    applicable_languages: [...langs].sort(),
    mapped_categories: mapCweToHarnessCategories(`CWE-${cweNum}`),
    priority: "P2",
  };
}

export function attachPriority(
  entries: CweTaxonomyEntry[],
  backlog: BacklogItem[]
): CweTaxonomyEntry[] {
  const tierByCwe = new Map(backlog.map((b) => [b.cwe, b.tier]));
  return entries.map((e) => ({
    ...e,
    priority: tierByCwe.get(e.cwe_id) ?? e.priority,
  }));
}
