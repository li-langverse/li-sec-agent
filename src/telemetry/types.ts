export type TelemetryEventType =
  | "pr_webhook_received"
  | "diff_fetched"
  | "static_scan_started"
  | "static_scan_completed"
  | "qwen_inference_started"
  | "qwen_inference_completed"
  | "qwen_inference_failed"
  | "finding_created"
  | "pr_comment_posted"
  | "user_feedback"
  | "false_positive_labeled"
  | "review_completed"
  | "review_failed";

export type BillingTier = "free" | "team" | "business" | "enterprise" | "on_prem";

export type UserFeedback =
  | "thumbs_up"
  | "thumbs_down"
  | "true_positive"
  | "false_positive"
  | "wont_fix"
  | "duplicate";

export interface TelemetryContext {
  orgId: string;
  tier: BillingTier;
  installationId?: string;
}

export interface TelemetryEventInput {
  eventType: TelemetryEventType;
  reviewId: string;
  repoFullName?: string;
  prNumber?: number;
  deliveryId?: string;
  commitSha?: string;
  diffHash?: string;
  linesScanned?: number;
  tokensIn?: number;
  tokensOut?: number;
  findingsCount?: number;
  modelId?: string;
  promptHash?: string;
  responseHash?: string;
  latencyMs?: number;
  findingId?: string;
  feedback?: UserFeedback;
  severity?: string;
  category?: string;
  source?: string;
  errorCode?: string;
  errorMessage?: string;
  payload?: Record<string, unknown>;
}

export interface TelemetryEventRecord extends TelemetryEventInput {
  id: string;
  occurredAt: string;
  orgId: string;
  tier: BillingTier;
  traceId?: string;
  spanId?: string;
  payloadJson?: string;
  errorMessageRedacted?: string;
}
