import type { QwenClient } from "../llm/qwen-client.js";
import type { TelemetryPipeline } from "../telemetry/pipeline.js";
import { hashContent } from "../telemetry/privacy.js";
import type { FindingRecord, PullRequestContext } from "../types.js";
import { randomUUID } from "node:crypto";

export interface ScannerFinding {
  finding: Omit<FindingRecord, "id" | "reviewId">;
}

export interface ScannerOrchestrator {
  scan(context: PullRequestContext, reviewId: string): Promise<ScannerFinding[]>;
}

const SECURITY_SYSTEM_PROMPT = `You are a security-focused code reviewer.
Analyze the pull request diff for vulnerabilities (injection, authz, secrets, crypto, unsafe dependencies).
Respond with a JSON array only. Each item: { "severity", "category", "title", "detail", "file_path", "line_start" }.
severity: info|low|medium|high|critical. category: injection|authz|secrets|crypto|dependency|config|other.
If no issues, return [].`;

export class QwenSecurityScanner implements ScannerOrchestrator {
  constructor(
    private readonly qwen: QwenClient,
    private readonly store?: { saveModelTrace: (input: {
      reviewId: string;
      modelId: string;
      prompt: string;
      response: string;
      promptTokens?: number;
      completionTokens?: number;
      latencyMs?: number;
    }) => void }
  ) {}

  async scan(
    context: PullRequestContext,
    reviewId: string
  ): Promise<ScannerFinding[]> {
    const completion = await this.qwen.complete(
      [
        { role: "system", content: SECURITY_SYSTEM_PROMPT },
        {
          role: "user",
          content: [
            `Repository: ${context.repoFullName}`,
            `PR: #${context.prNumber}`,
            `Commit: ${context.headSha}`,
            "Diff:",
            context.diffText.slice(0, 120_000),
          ].join("\n"),
        },
      ],
      {
        reviewId,
        repoFullName: context.repoFullName,
        prNumber: context.prNumber,
      }
    );

    this.store?.saveModelTrace({
      reviewId,
      modelId: completion.model,
      prompt: hashContent(context.diffText),
      response: completion.content,
      promptTokens: completion.promptTokens,
      completionTokens: completion.completionTokens,
      latencyMs: completion.latencyMs,
    });

    const parsed = parseFindingsJson(completion.content);
    return parsed.map((row) => ({
      finding: {
        reviewId,
        filePath: row.file_path,
        lineStart: row.line_start,
        lineEnd: row.line_end,
        severity: normalizeSeverity(row.severity),
        category: normalizeCategory(row.category),
        title: row.title ?? "Security finding",
        detail: row.detail,
        source: "qwen",
        modelId: completion.model,
        promptTokens: completion.promptTokens,
        completionTokens: completion.completionTokens,
        latencyMs: completion.latencyMs,
      },
    }));
  }
}

export class StaticScannerStub implements ScannerOrchestrator {
  constructor(private readonly telemetry?: TelemetryPipeline) {}

  async scan(
    context: PullRequestContext,
    reviewId: string
  ): Promise<ScannerFinding[]> {
    this.telemetry?.emit({
      eventType: "static_scan_started",
      reviewId,
      repoFullName: context.repoFullName,
      prNumber: context.prNumber,
      diffHash: context.diffHash,
    });
    const findings: ScannerFinding[] = [];
    this.telemetry?.emit({
      eventType: "static_scan_completed",
      reviewId,
      repoFullName: context.repoFullName,
      prNumber: context.prNumber,
      findingsCount: findings.length,
    });
    return findings;
  }
}

export class CompositeScanner implements ScannerOrchestrator {
  constructor(private readonly scanners: ScannerOrchestrator[]) {}

  async scan(
    context: PullRequestContext,
    reviewId: string
  ): Promise<ScannerFinding[]> {
    const batches = await Promise.all(
      this.scanners.map((s) => s.scan(context, reviewId))
    );
    return batches.flat();
  }
}

export function createReviewId(): string {
  return randomUUID();
}

type RawFinding = {
  severity?: string;
  category?: string;
  title?: string;
  detail?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
};

function parseFindingsJson(text: string): RawFinding[] {
  const trimmed = text.trim();
  const jsonBlock = trimmed.match(/```json\s*([\s\S]*?)```/i)?.[1] ?? trimmed;
  try {
    const data = JSON.parse(jsonBlock) as unknown;
    return Array.isArray(data) ? (data as RawFinding[]) : [];
  } catch {
    return [];
  }
}

function normalizeSeverity(value?: string): FindingRecord["severity"] {
  const allowed = ["info", "low", "medium", "high", "critical"] as const;
  return allowed.includes(value as (typeof allowed)[number])
    ? (value as FindingRecord["severity"])
    : "medium";
}

function normalizeCategory(value?: string): FindingRecord["category"] {
  const allowed = [
    "injection",
    "authz",
    "secrets",
    "crypto",
    "dependency",
    "config",
    "other",
  ] as const;
  return allowed.includes(value as (typeof allowed)[number])
    ? (value as FindingRecord["category"])
    : "other";
}
