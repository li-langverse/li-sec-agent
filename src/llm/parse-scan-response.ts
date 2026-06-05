import type {
  FindingCategory,
  FindingSeverity,
  MitigationEffort,
  MitigationRecord,
  ScanIssue,
} from "../types.js";

export type RawLineRange = { start?: number; end?: number };

export type RawFinding = {
  severity?: string;
  category?: string;
  cwe_id?: string | null;
  title?: string;
  detail?: string;
  file_path?: string;
  line_range?: RawLineRange;
  line_start?: number;
  line_end?: number;
  evidence?: string;
  confidence?: number;
};

export type RawMitigation = {
  title?: string;
  description?: string;
  suggested_patch?: string;
  references?: string[];
  effort?: string;
  alternative_approaches?: string[];
};

export type RawScanItem = {
  finding?: RawFinding;
  mitigation?: RawMitigation;
  // legacy flat shape
  severity?: string;
  category?: string;
  title?: string;
  detail?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
};

const SEVERITIES: readonly FindingSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];
const CATEGORIES: readonly FindingCategory[] = [
  "injection",
  "authz",
  "secrets",
  "crypto",
  "dependency",
  "config",
  "other",
];
const EFFORTS: readonly MitigationEffort[] = ["low", "medium", "high"];

export function extractJsonArray(text: string): unknown {
  const trimmed = text.trim();
  const jsonBlock = trimmed.match(/```json\s*([\s\S]*?)```/i)?.[1] ?? trimmed;
  return JSON.parse(jsonBlock);
}

export function parseScanResponse(text: string): RawScanItem[] {
  try {
    const data = extractJsonArray(text);
    return Array.isArray(data) ? (data as RawScanItem[]) : [];
  } catch {
    return [];
  }
}

export function normalizeSeverity(value?: string): FindingSeverity {
  return SEVERITIES.includes(value as FindingSeverity)
    ? (value as FindingSeverity)
    : "medium";
}

export function normalizeCategory(value?: string): FindingCategory {
  return CATEGORIES.includes(value as FindingCategory)
    ? (value as FindingCategory)
    : "other";
}

export function normalizeEffort(value?: string): MitigationEffort {
  return EFFORTS.includes(value as MitigationEffort)
    ? (value as MitigationEffort)
    : "medium";
}

export function clampConfidence(value?: number): number | undefined {
  if (value === undefined || Number.isNaN(value)) return undefined;
  return Math.min(1, Math.max(0, value));
}

export function resolveLineRange(raw: RawFinding): {
  lineStart?: number;
  lineEnd?: number;
} {
  if (raw.line_range?.start !== undefined) {
    return {
      lineStart: raw.line_range.start,
      lineEnd: raw.line_range.end ?? raw.line_range.start,
    };
  }
  return {
    lineStart: raw.line_start,
    lineEnd: raw.line_end ?? raw.line_start,
  };
}

export function normalizeScanItem(
  row: RawScanItem,
  defaults: { source: "qwen"; modelId?: string }
): ScanIssue | null {
  const findingRaw: RawFinding = row.finding ?? row;
  const mitigationRaw: RawMitigation | undefined = row.mitigation;

  const title = findingRaw.title?.trim();
  if (!title) return null;

  const { lineStart, lineEnd } = resolveLineRange(findingRaw);

  const finding = {
    filePath: findingRaw.file_path,
    lineStart,
    lineEnd,
    severity: normalizeSeverity(findingRaw.severity),
    category: normalizeCategory(findingRaw.category),
    title,
    detail: findingRaw.detail,
    cwe: findingRaw.cwe_id ?? undefined,
    evidence: findingRaw.evidence,
    confidence: clampConfidence(findingRaw.confidence),
    source: defaults.source,
    modelId: defaults.modelId,
  };

  const mitigation: Omit<MitigationRecord, "id" | "findingId" | "contentHash"> =
    mitigationRaw
      ? {
          title: mitigationRaw.title?.trim() || `Fix: ${title}`,
          description:
            mitigationRaw.description?.trim() ||
            "Apply secure coding practices for this vulnerability class.",
          suggestedPatch: mitigationRaw.suggested_patch,
          references: Array.isArray(mitigationRaw.references)
            ? mitigationRaw.references.filter((r) => typeof r === "string")
            : [],
          effort: normalizeEffort(mitigationRaw.effort),
          alternativeApproaches: Array.isArray(
            mitigationRaw.alternative_approaches
          )
            ? mitigationRaw.alternative_approaches.filter(
                (a) => typeof a === "string"
              )
            : [],
        }
      : {
          title: `Remediate: ${title}`,
          description:
            "Review the finding and apply the appropriate secure pattern for this vulnerability category.",
          references: [],
          effort: "medium" as MitigationEffort,
          alternativeApproaches: [],
        };

  return { finding, mitigation };
}

export function parseAndNormalizeScanResponse(
  text: string,
  defaults: { source: "qwen"; modelId?: string }
): ScanIssue[] {
  return parseScanResponse(text)
    .map((row) => normalizeScanItem(row, defaults))
    .filter((item): item is ScanIssue => item !== null);
}
