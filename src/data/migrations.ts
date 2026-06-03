import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type Database from "better-sqlite3";

export function applyMigrations(db: Database.Database): void {
  const dir = join(fileURLToPath(new URL("../..", import.meta.url)), "migrations");
  const files = readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const file of files) {
    db.exec(readFileSync(join(dir, file), "utf8"));
  }
}
