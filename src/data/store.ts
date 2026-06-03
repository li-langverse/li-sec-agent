import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import type { FindingRecord, PrReviewRecord, PullRequestContext } from "../types.js";
import { hashContent } from "../telemetry/privacy.js";
import { applyMigrations } from "./migrations.js";

export interface DataStore {
  db: Database.Database;
  createReview(context: PullRequestContext): PrReviewRecord;
  saveFindings(reviewId: string, findings: FindingRecord[]): void;
  saveModelTrace(input: {
    reviewId: string;
    modelId: string;
    prompt: string;
    response: string;
    promptTokens?: number;
    completionTokens?: number;
    latencyMs?: number;
  }): void;
  listFindings(reviewId: string): FindingRecord[];
}

export function hashText(value: string): string {
  return hashContent(value);
}

export function createSqliteStore(databaseUrl: string): DataStore {
  const path = databaseUrl.replace(/^sqlite:/, "");
  mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  applyMigrations(db);

  const insertReview = db.prepare(`
    INSERT INTO pr_reviews (id, delivery_id, repo_full_name, pr_number, head_sha, diff_hash, status)
    VALUES (@id, @deliveryId, @repoFullName, @prNumber, @headSha, @diffHash, @status)
  `);

  const insertFinding = db.prepare(`
    INSERT INTO findings (
      id, review_id, file_path, line_start, line_end, severity, category, title, detail, cwe, source,
      model_id, prompt_tokens, completion_tokens, latency_ms
    ) VALUES (
      @id, @reviewId, @filePath, @lineStart, @lineEnd, @severity, @category, @title, @detail, @cwe, @source,
      @modelId, @promptTokens, @completionTokens, @latencyMs
    )
  `);

  const insertTrace = db.prepare(`
    INSERT INTO model_traces (
      id, review_id, model_id, prompt_hash, response_hash, prompt_tokens, completion_tokens, latency_ms
    ) VALUES (
      @id, @reviewId, @modelId, @promptHash, @responseHash, @promptTokens, @completionTokens, @latencyMs
    )
  `);

  const selectFindings = db.prepare(`
    SELECT * FROM findings WHERE review_id = @reviewId ORDER BY created_at ASC
  `);

  return {
    db,

    createReview(context) {
      const record: PrReviewRecord = {
        id: randomUUID(),
        deliveryId: context.deliveryId,
        repoFullName: context.repoFullName,
        prNumber: context.prNumber,
        headSha: context.headSha,
        diffHash: context.diffHash,
        status: "pending",
      };
      insertReview.run({
        id: record.id,
        deliveryId: record.deliveryId,
        repoFullName: record.repoFullName,
        prNumber: record.prNumber,
        headSha: record.headSha,
        diffHash: record.diffHash,
        status: record.status,
      });
      return record;
    },

    saveFindings(reviewId, findings) {
      for (const f of findings) {
        insertFinding.run({
          id: f.id ?? randomUUID(),
          reviewId,
          filePath: f.filePath ?? null,
          lineStart: f.lineStart ?? null,
          lineEnd: f.lineEnd ?? null,
          severity: f.severity,
          category: f.category,
          title: f.title,
          detail: f.detail ?? null,
          cwe: f.cwe ?? null,
          source: f.source,
          modelId: f.modelId ?? null,
          promptTokens: f.promptTokens ?? null,
          completionTokens: f.completionTokens ?? null,
          latencyMs: f.latencyMs ?? null,
        });
      }
    },

    saveModelTrace(input) {
      insertTrace.run({
        id: randomUUID(),
        reviewId: input.reviewId,
        modelId: input.modelId,
        promptHash: hashContent(input.prompt),
        responseHash: hashContent(input.response),
        promptTokens: input.promptTokens ?? null,
        completionTokens: input.completionTokens ?? null,
        latencyMs: input.latencyMs ?? null,
      });
    },

    listFindings(reviewId) {
      return selectFindings.all({ reviewId }) as FindingRecord[];
    },
  };
}
