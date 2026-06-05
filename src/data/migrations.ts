import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type Database from "better-sqlite3";

export function applyMigrations(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename TEXT PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  const applied = new Set(
    (
      db.prepare("SELECT filename FROM schema_migrations").all() as Array<{
        filename: string;
      }>
    ).map((row) => row.filename)
  );

  const insertApplied = db.prepare(
    "INSERT INTO schema_migrations (filename) VALUES (@filename)"
  );

  const dir = join(fileURLToPath(new URL("../..", import.meta.url)), "migrations");
  const files = readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of files) {
    if (applied.has(file)) continue;
    db.exec(readFileSync(join(dir, file), "utf8"));
    insertApplied.run({ filename: file });
  }
}
