/**
 * MITRE REST enricher — builds eval/cwe-taxonomy.json from expansion backlog.
 *
 * Usage:
 *   npx tsx scripts/benchmarks/cwe-enrich-mitre.ts
 *   MITRE_DELAY_MS=400 npx tsx scripts/benchmarks/cwe-enrich-mitre.ts
 */

import { writeFileSync } from "node:fs";
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
  const ids = backlogCweIds(backlog);
  const delayMs = Number(process.env.MITRE_DELAY_MS ?? "350");
  const entries: CweTaxonomyEntry[] = [];

  console.log(`Enriching ${ids.length} CWEs from backlog (delay ${delayMs}ms)...`);

  for (const cwe of ids) {
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

  const outPath = join(REPO_ROOT, "eval", "cwe-taxonomy.json");
  writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n", "utf8");
  console.log(`Wrote ${enriched.length} entries -> ${outPath}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
