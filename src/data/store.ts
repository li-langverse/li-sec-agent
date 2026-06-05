import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import type {
  FindingRecord,
  MitigationRecord,
  PrReviewRecord,
  PullRequestContext,
  ScanIssue,
} from "../types.js";
import { hashContent } from "../telemetry/privacy.js";
import { applyMigrations } from "./migrations.js";

export interface DataStore {
  db: Database.Database;
  createReview(context: PullRequestContext): PrReviewRecord;
  saveFindings(reviewId: string, findings: FindingRecord[]): void;
  saveScanResults(
    reviewId: string,
    results: Array<{ finding: FindingRecord; mitigation: MitigationRecord }>
  ): void;
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
  listMitigations(reviewId: string): MitigationRecord[];
}

export function hashMitigationContent(input: {
  title: string;
  description: string;
  suggestedPatch?: string;
  effort: string;
}): string {
  return hashContent(
    JSON.stringify({
      title: input.title,
      description: input.description,
      effort: input.effort,
      patch: input.suggestedPatch ?? "",
    })
  );
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
      id, review_id, file_path, line_start, line_end, severity, category, title, detail, cwe,
      evidence, confidence, source,
      model_id, prompt_tokens, completion_tokens, latency_ms
    ) VALUES (
      @id, @reviewId, @filePath, @lineStart, @lineEnd, @severity, @category, @title, @detail, @cwe,
      @evidence, @confidence, @source,
      @modelId, @promptTokens, @completionTokens, @latencyMs
    )
  `);

  const insertMitigation = db.prepare(`
    INSERT INTO mitigations (
      id, finding_id, title, description, suggested_patch, references_json,
      effort, alternative_approaches_json, content_hash
    ) VALUES (
      @id, @findingId, @title, @description, @suggestedPatch, @referencesJson,
      @effort, @alternativeApproachesJson, @contentHash
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

  const selectMitigations = db.prepare(`
    SELECT m.* FROM mitigations m
    JOIN findings f ON f.id = m.finding_id
    WHERE f.review_id = @reviewId
    ORDER BY m.created_at ASC
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
          evidence: f.evidence ?? null,
          confidence: f.confidence ?? null,
          source: f.source,
          modelId: f.modelId ?? null,
          promptTokens: f.promptTokens ?? null,
          completionTokens: f.completionTokens ?? null,
          latencyMs: f.latencyMs ?? null,
        });
      }
    },

    saveScanResults(reviewId, results) {
      for (const { finding, mitigation } of results) {
        insertFinding.run({
          id: finding.id,
          reviewId,
          filePath: finding.filePath ?? null,
          lineStart: finding.lineStart ?? null,
          lineEnd: finding.lineEnd ?? null,
          severity: finding.severity,
          category: finding.category,
          title: finding.title,
          detail: finding.detail ?? null,
          cwe: finding.cwe ?? null,
          evidence: finding.evidence ?? null,
          confidence: finding.confidence ?? null,
          source: finding.source,
          modelId: finding.modelId ?? null,
          promptTokens: finding.promptTokens ?? null,
          completionTokens: finding.completionTokens ?? null,
          latencyMs: finding.latencyMs ?? null,
        });
        insertMitigation.run({
          id: mitigation.id,
          findingId: finding.id,
          title: mitigation.title,
          description: mitigation.description,
          suggestedPatch: mitigation.suggestedPatch ?? null,
          referencesJson: JSON.stringify(mitigation.references),
          effort: mitigation.effort,
          alternativeApproachesJson: JSON.stringify(
            mitigation.alternativeApproaches
          ),
          contentHash: mitigation.contentHash,
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

    listMitigations(reviewId) {
      const rows = selectMitigations.all({ reviewId }) as Array<{
        id: string;
        finding_id: string;
        title: string;
        description: string;
        suggested_patch: string | null;
        references_json: string;
        effort: MitigationRecord["effort"];
        alternative_approaches_json: string;
        content_hash: string;
      }>;
      return rows.map((row) => ({
        id: row.id,
        findingId: row.finding_id,
        title: row.title,
        description: row.description,
        suggestedPatch: row.suggested_patch ?? undefined,
        references: JSON.parse(row.references_json) as string[],
        effort: row.effort,
        alternativeApproaches: JSON.parse(
          row.alternative_approaches_json
        ) as string[],
        contentHash: row.content_hash,
      }));
    },
  };
}

export function scanIssuesToRecords(
  reviewId: string,
  issues: ScanIssue[],
  ids?: { findingId?: string; mitigationId?: string }[]
): Array<{ finding: FindingRecord; mitigation: MitigationRecord }> {
  return issues.map((issue, index) => {
    const findingId = ids?.[index]?.findingId ?? randomUUID();
    const mitigationId = ids?.[index]?.mitigationId ?? randomUUID();
    const contentHash = hashMitigationContent({
      title: issue.mitigation.title,
      description: issue.mitigation.description,
      suggestedPatch: issue.mitigation.suggestedPatch,
      effort: issue.mitigation.effort,
    });
    return {
      finding: { ...issue.finding, id: findingId, reviewId },
      mitigation: {
        ...issue.mitigation,
        id: mitigationId,
        findingId,
        contentHash,
      },
    };
  });
}
