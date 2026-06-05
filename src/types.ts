export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type FindingCategory =
  | "injection"
  | "authz"
  | "secrets"
  | "crypto"
  | "dependency"
  | "config"
  | "other";
export type FindingSource = "static" | "qwen" | "human" | "rulepack";
export type MitigationEffort = "low" | "medium" | "high";

export interface PrReviewRecord {
  id: string;
  deliveryId: string;
  repoFullName: string;
  prNumber: number;
  headSha: string;
  diffHash: string;
  status: "pending" | "running" | "completed" | "failed";
}

export interface FindingRecord {
  id: string;
  reviewId: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  severity: FindingSeverity;
  category: FindingCategory;
  title: string;
  detail?: string;
  cwe?: string;
  evidence?: string;
  confidence?: number;
  source: FindingSource;
  modelId?: string;
  promptTokens?: number;
  completionTokens?: number;
  latencyMs?: number;
}

export interface MitigationRecord {
  id: string;
  findingId: string;
  title: string;
  description: string;
  suggestedPatch?: string;
  references: string[];
  effort: MitigationEffort;
  alternativeApproaches: string[];
  contentHash: string;
}

/** Scanner output: paired finding + mitigation per issue. */
export interface ScanIssue {
  finding: Omit<FindingRecord, "id" | "reviewId">;
  mitigation: Omit<MitigationRecord, "id" | "findingId" | "contentHash">;
}

export interface PullRequestContext {
  deliveryId: string;
  repoFullName: string;
  prNumber: number;
  headSha: string;
  baseSha: string;
  diffText: string;
  diffHash: string;
}
