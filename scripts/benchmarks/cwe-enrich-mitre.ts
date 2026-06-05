/**
 * MITRE REST enricher — builds eval/cwe-taxonomy.json from expansion backlog.
 *
 * Usage:
 *   npx tsx scripts/benchmarks/cwe-enrich-mitre.ts
 *   MITRE_DELAY_MS=400 npx tsx scripts/benchmarks/cwe-enrich-mitre.ts
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  REPO_ROOT,
  attachPriority,
  backlogCweIds,
  fetchMitreWeakness,
  loadBacklog,
  parseCweNumber,
  type CweTaxonomyEntry,
} from "./cwe-shared.js";

async function main(): Promise<void> {
  const backlog = loadBacklog();
  const allIds = backlogCweIds(backlog);
  const offset = Number(process.env.MITRE_OFFSET ?? "0");
  const limit = Number(process.env.MITRE_LIMIT ?? "0");
  const ids =
    limit > 0 ? allIds.slice(offset, offset + limit) : allIds.slice(offset);
  const delayMs = Number(process.env.MITRE_DELAY_MS ?? "350");
  const outPath = join(REPO_ROOT, "eval", "cwe-taxonomy.json");
  const dataOutPath =
    process.env.REFERENCE_DATA_DIR != null
      ? join(process.env.REFERENCE_DATA_DIR, "cwe-taxonomy.json")
      : outPath;

  const existingByCwe = new Map<string, CweTaxonomyEntry>();
  for (const path of [dataOutPath, outPath]) {
    if (!existsSync(path)) continue;
    const prev = JSON.parse(readFileSync(path, "utf8")) as { entries?: CweTaxonomyEntry[] };
    for (const e of prev.entries ?? []) existingByCwe.set(e.cwe_id, e);
    break;
  }

  const entries: CweTaxonomyEntry[] = [...existingByCwe.values()];
  const toFetch = ids.filter((cwe) => !existingByCwe.has(cwe));

  console.log(
    `Enriching ${toFetch.length}/${ids.length} CWEs (offset ${offset}, delay ${delayMs}ms)...`
  );

  for (const cwe of toFetch) {
    const num = parseCweNumber(cwe);
    process.stdout.write(`  CWE-${num}... `);
    const row = await fetchMitreWeakness(num, delayMs);
    if (row) {
      const tier = backlog.find((b) => b.cwe === cwe)?.tier ?? "P2";
      entries.push({ ...row, priority: tier });
      console.log(row.name);
    } else {
      const fallback = backlog.find((b) => b.cwe === cwe);
      entries.push({
        id: num,
        cwe_id: cwe,
        name: fallback?.name ?? cwe,
        description: "",
        abstraction: "",
        status: "",
        related_weaknesses: [],
        applicable_languages: fallback?.languages ?? [],
        mapped_categories: [],
        priority: fallback?.tier ?? "P2",
      });
      console.log("(fallback from backlog)");
    }
  }

  const enriched = attachPriority(entries, backlog);
  const out = {
    version: 1,
    generated_at: new Date().toISOString(),
    source: "https://cwe-api.mitre.org/api/v1/cwe/weakness/{id}",
    entry_count: enriched.length,
    entries: enriched,
  };

  writeFileSync(dataOutPath, JSON.stringify(out, null, 2) + "\n", "utf8");
  console.log(`Wrote ${enriched.length} entries -> ${dataOutPath}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
