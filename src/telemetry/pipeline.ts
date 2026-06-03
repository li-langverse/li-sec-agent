import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { redactSecrets, safePayload } from "./privacy.js";
import { OtelBridge } from "./otel.js";
import type {
  BillingTier,
  TelemetryContext,
  TelemetryEventInput,
  TelemetryEventRecord,
} from "./types.js";

export interface TelemetryPipelineOptions {
  db: Database.Database;
  context: TelemetryContext;
  otel?: OtelBridge;
}

export class TelemetryPipeline {
  private readonly db: Database.Database;
  private readonly context: TelemetryContext;
  private readonly otel: OtelBridge;
  private readonly insertEvent;

  constructor(options: TelemetryPipelineOptions) {
    this.db = options.db;
    this.context = options.context;
    this.otel = options.otel ?? new OtelBridge();
    this.insertEvent = this.db.prepare(`
      INSERT INTO telemetry_events (
        id, event_type, occurred_at, org_id, installation_id, repo_full_name, pr_number,
        review_id, delivery_id, commit_sha, diff_hash, lines_scanned, tokens_in, tokens_out,
        findings_count, tier, model_id, prompt_hash, response_hash, latency_ms, finding_id,
        feedback, severity, category, source, error_code, error_message_redacted,
        trace_id, span_id, payload_json
      ) VALUES (
        @id, @eventType, @occurredAt, @orgId, @installationId, @repoFullName, @prNumber,
        @reviewId, @deliveryId, @commitSha, @diffHash, @linesScanned, @tokensIn, @tokensOut,
        @findingsCount, @tier, @modelId, @promptHash, @responseHash, @latencyMs, @findingId,
        @feedback, @severity, @category, @source, @errorCode, @errorMessageRedacted,
        @traceId, @spanId, @payloadJson
      )
    `);
  }

  emit(input: TelemetryEventInput): TelemetryEventRecord {
    const span = this.otel.startSpan(input.eventType);
    const record: TelemetryEventRecord = {
      ...input,
      id: randomUUID(),
      occurredAt: new Date().toISOString(),
      orgId: this.context.orgId,
      tier: this.context.tier,
      traceId: span.traceId,
      spanId: span.spanId,
      errorMessageRedacted: input.errorMessage
        ? redactSecrets(input.errorMessage)
        : undefined,
      payloadJson: input.payload ? safePayload(input.payload) : undefined,
    };

    this.insertEvent.run({
      id: record.id,
      eventType: record.eventType,
      occurredAt: record.occurredAt,
      orgId: record.orgId,
      installationId: this.context.installationId ?? null,
      repoFullName: record.repoFullName ?? null,
      prNumber: record.prNumber ?? null,
      reviewId: record.reviewId,
      deliveryId: record.deliveryId ?? null,
      commitSha: record.commitSha ?? null,
      diffHash: record.diffHash ?? null,
      linesScanned: record.linesScanned ?? null,
      tokensIn: record.tokensIn ?? null,
      tokensOut: record.tokensOut ?? null,
      findingsCount: record.findingsCount ?? null,
      tier: record.tier,
      modelId: record.modelId ?? null,
      promptHash: record.promptHash ?? null,
      responseHash: record.responseHash ?? null,
      latencyMs: record.latencyMs ?? null,
      findingId: record.findingId ?? null,
      feedback: record.feedback ?? null,
      severity: record.severity ?? null,
      category: record.category ?? null,
      source: record.source ?? null,
      errorCode: record.errorCode ?? null,
      errorMessageRedacted: record.errorMessageRedacted ?? null,
      traceId: record.traceId ?? null,
      spanId: record.spanId ?? null,
      payloadJson: record.payloadJson ?? null,
    });

    console.log(
      JSON.stringify({
        level: "info",
        msg: "telemetry_event",
        event_type: record.eventType,
        review_id: record.reviewId,
        org_id: record.orgId,
        trace_id: record.traceId,
      })
    );

    span.end({ review_id: record.reviewId });
    void this.otel.recordEvent(record);
    return record;
  }

  recordUsageMetering(input: {
    reviewId: string;
    repoFullName: string;
    prNumber: number;
    linesScanned: number;
    tokensIn: number;
    tokensOut: number;
    findingsCount: number;
    staticFindings: number;
    qwenFindings: number;
  }): void {
    const stmt = this.db.prepare(`
      INSERT INTO usage_metering (
        id, review_id, org_id, repo_full_name, pr_number, tier,
        lines_scanned, tokens_in, tokens_out, findings_count,
        static_findings, qwen_findings
      ) VALUES (
        @id, @reviewId, @orgId, @repoFullName, @prNumber, @tier,
        @linesScanned, @tokensIn, @tokensOut, @findingsCount,
        @staticFindings, @qwenFindings
      )
      ON CONFLICT(review_id) DO UPDATE SET
        lines_scanned = excluded.lines_scanned,
        tokens_in = excluded.tokens_in,
        tokens_out = excluded.tokens_out,
        findings_count = excluded.findings_count,
        static_findings = excluded.static_findings,
        qwen_findings = excluded.qwen_findings,
        recorded_at = datetime('now')
    `);
    stmt.run({
      id: randomUUID(),
      reviewId: input.reviewId,
      orgId: this.context.orgId,
      repoFullName: input.repoFullName,
      prNumber: input.prNumber,
      tier: this.context.tier,
      linesScanned: input.linesScanned,
      tokensIn: input.tokensIn,
      tokensOut: input.tokensOut,
      findingsCount: input.findingsCount,
      staticFindings: input.staticFindings,
      qwenFindings: input.qwenFindings,
    });
  }
}

export function loadTelemetryContext(): TelemetryContext {
  return {
    orgId: process.env.SECAGENT_ORG_ID ?? "homelab",
    tier: (process.env.SECAGENT_TIER as BillingTier | undefined) ?? "free",
    installationId: process.env.GITHUB_APP_INSTALLATION_ID,
  };
}

export function createOtelBridge(): OtelBridge {
  return new OtelBridge({
    endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
    serviceName: process.env.OTEL_SERVICE_NAME ?? "li-sec-agent",
  });
}
