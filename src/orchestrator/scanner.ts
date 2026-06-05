import type { QwenClient } from "../llm/qwen-client.js";
import { parseAndNormalizeScanResponse } from "../llm/parse-scan-response.js";
import {
  buildSecurityUserPrompt,
  SECURITY_REVIEWER_SYSTEM_PROMPT,
} from "../llm/security-prompt.js";
import type { TelemetryPipeline } from "../telemetry/pipeline.js";
import { hashContent } from "../telemetry/privacy.js";
import type { ScanIssue, PullRequestContext } from "../types.js";
import { randomUUID } from "node:crypto";

export interface ScannerOrchestrator {
  scan(context: PullRequestContext, reviewId: string): Promise<ScanIssue[]>;
}

export class QwenSecurityScanner implements ScannerOrchestrator {
  constructor(
    private readonly qwen: QwenClient,
    private readonly store?: {
      saveModelTrace: (input: {
        reviewId: string;
        modelId: string;
        prompt: string;
        response: string;
        promptTokens?: number;
        completionTokens?: number;
        latencyMs?: number;
      }) => void;
    },
    private readonly telemetry?: TelemetryPipeline
  ) {}

  async scan(
    context: PullRequestContext,
    reviewId: string
  ): Promise<ScanIssue[]> {
    const completion = await this.qwen.complete(
      [
        { role: "system", content: SECURITY_REVIEWER_SYSTEM_PROMPT },
        {
          role: "user",
          content: buildSecurityUserPrompt({
            repoFullName: context.repoFullName,
            prNumber: context.prNumber,
            headSha: context.headSha,
            diffText: context.diffText,
          }),
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

    const issues = parseAndNormalizeScanResponse(completion.content, {
      source: "qwen",
      modelId: completion.model,
    });

    return issues.map((issue) => ({
      finding: {
        ...issue.finding,
        promptTokens: completion.promptTokens,
        completionTokens: completion.completionTokens,
        latencyMs: completion.latencyMs,
      },
      mitigation: issue.mitigation,
    }));
  }
}

export class StaticScannerStub implements ScannerOrchestrator {
  constructor(private readonly telemetry?: TelemetryPipeline) {}

  async scan(
    context: PullRequestContext,
    reviewId: string
  ): Promise<ScanIssue[]> {
    this.telemetry?.emit({
      eventType: "static_scan_started",
      reviewId,
      repoFullName: context.repoFullName,
      prNumber: context.prNumber,
      diffHash: context.diffHash,
    });
    const findings: ScanIssue[] = [];
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
  ): Promise<ScanIssue[]> {
    const batches = await Promise.all(
      this.scanners.map((s) => s.scan(context, reviewId))
    );
    return batches.flat();
  }
}

export function createReviewId(): string {
  return randomUUID();
}
