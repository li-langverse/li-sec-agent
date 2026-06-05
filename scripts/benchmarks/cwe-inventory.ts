/**
 * Phase 0 — CWE homelab mirror inventory.
 * Fetches static catalog from cwe.klaut.pro (or CWE_MIRROR_URL) and prints stats.
 *
 * Usage:
 *   npx tsx scripts/benchmarks/cwe-inventory.ts
 *   CWE_MIRROR_URL=http://192.168.10.33:30483 npx tsx scripts/benchmarks/cwe-inventory.ts
 *   CWE_MIRROR_URL=http://cwe-mirror.cwe.svc.cluster.local:8080 npx tsx scripts/benchmarks/cwe-inventory.ts
 *
 * Optional (future edge auth):
 *   CWE_MIRROR_API_TOKEN=... npx tsx scripts/benchmarks/cwe-inventory.ts
 *
 * Enrichment (descriptions, relationships) — not on mirror; use MITRE REST per id:
 *   https://cwe-api.mitre.org/api/v1/cwe/weakness/{id}
 */

const DEFAULT_MIRROR = "https://cwe.klaut.pro";

type Manifest = {
  source_url: string;
  sha256: string;
  synced_at: string;
  catalog: { name: string; version: string; date: string };
  weakness_count: number;
  mitre_rest_api: string;
};

type WeaknessIndex = {
  id: number;
  name: string;
  abstraction: string;
  status: string;
  structure?: string;
};

async function fetchJson<T>(base: string, path: string, token?: string): Promise<T> {
  const url = new URL(path, base.endsWith("/") ? base : `${base}/`);
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`${url} → HTTP ${res.status}`);
  return (await res.json()) as T;
}

function tally(items: WeaknessIndex[], key: keyof WeaknessIndex): Record<string, number> {
  const out: Record<string, number> = {};
  for (const w of items) {
    const v = String(w[key] ?? "(missing)");
    out[v] = (out[v] ?? 0) + 1;
  }
  return out;
}

async function main(): Promise<void> {
  const base = (process.env.CWE_MIRROR_URL ?? DEFAULT_MIRROR).replace(/\/$/, "");
  const token = process.env.CWE_MIRROR_API_TOKEN;

  console.log(`Mirror: ${base}`);
  const manifest = await fetchJson<Manifest>(base, "/manifest.json", token);
  const weaknesses = await fetchJson<WeaknessIndex[]>(base, "/weaknesses.json", token);

  const emptyNames = weaknesses.filter((w) => !w.name?.trim()).length;
  const report = {
    mirror: base,
    catalog: manifest.catalog,
    synced_at: manifest.synced_at,
    sha256: manifest.sha256,
    weakness_count_manifest: manifest.weakness_count,
    weakness_count_fetched: weaknesses.length,
    mitre_rest_api: manifest.mitre_rest_api,
    abstraction: tally(weaknesses, "abstraction"),
    status: tally(weaknesses, "status"),
    structure: tally(weaknesses, "structure"),
    index_names_populated: weaknesses.length - emptyNames,
    index_names_empty: emptyNames,
    note:
      "Mirror is CWE taxonomy only (no CVE/exploit records). Names in weaknesses.json may be empty — enrich via MITRE REST.",
  };

  console.log(JSON.stringify(report, null, 2));

  if (process.env.WRITE_SNAPSHOT === "1" || process.argv.includes("--write-snapshot")) {
    const { writeFileSync } = await import("node:fs");
    const { join, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
    const dataDir = process.env.REFERENCE_DATA_DIR ?? join(root, "eval");
    const snapshot = {
      generated_at: new Date().toISOString(),
      manifest,
      weaknesses,
      report,
    };
    const out = join(dataDir, "cwe-mirror-snapshot.json");
    writeFileSync(out, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
    console.log(`Wrote snapshot -> ${out}`);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
