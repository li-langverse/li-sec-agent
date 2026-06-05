/**
 * Paths for reference corpus build — supports homelab worker PVC via REFERENCE_DATA_DIR.
 */

import { join } from "node:path";
import { REPO_ROOT } from "./cwe-shared.js";

/** Writable corpus dir (PVC mount in cluster). Defaults to repo eval/reference-database. */
export function referenceDataDir(): string {
  return process.env.REFERENCE_DATA_DIR ?? join(REPO_ROOT, "eval", "reference-database");
}

export function workerStatePath(): string {
  return join(referenceDataDir(), "worker-state.json");
}

export function progressLogPath(): string {
  return join(referenceDataDir(), "expansion-progress.jsonl");
}
