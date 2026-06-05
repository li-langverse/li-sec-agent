import type { FindingRecord, MitigationRecord } from "./types.js";

export interface ReviewCommentItem {
  finding: FindingRecord;
  mitigation: MitigationRecord;
}

export interface GitHubReviewComment {
  /** File path for inline comment (Pull Request Review API). */
  path?: string;
  /** Line in the file at head commit. */
  line?: number;
  side?: "RIGHT" | "LEFT";
  /** Diff position when webhook provides patch position (preferred for inline). */
  position?: number;
  body: string;
}

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

export function formatLocation(finding: FindingRecord): string {
  if (!finding.filePath) return "—";
  const line =
    finding.lineStart !== undefined
      ? finding.lineEnd && finding.lineEnd !== finding.lineStart
        ? `${finding.lineStart}-${finding.lineEnd}`
        : String(finding.lineStart)
      : "?";
  return `\`${finding.filePath}:${line}\``;
}

export function formatFindingBlock(finding: FindingRecord): string {
  const emoji = SEVERITY_EMOJI[finding.severity] ?? "•";
  const parts = [
    `### ${emoji} ${finding.title}`,
    "",
    `| | |`,
    `|---|---|`,
    `| **Severity** | \`${finding.severity}\` |`,
    `| **Category** | \`${finding.category}\` |`,
    `| **Location** | ${formatLocation(finding)} |`,
  ];
  if (finding.cwe) {
    parts.push(`| **CWE** | [${finding.cwe}](https://cwe.mitre.org/data/definitions/${finding.cwe.replace(/^CWE-/, "")}.html) |`);
  }
  if (finding.confidence !== undefined) {
    parts.push(`| **Confidence** | ${Math.round(finding.confidence * 100)}% |`);
  }
  if (finding.detail) {
    parts.push("", finding.detail);
  }
  if (finding.evidence) {
    parts.push("", "**Evidence:**", "```", finding.evidence, "```");
  }
  return parts.join("\n");
}

export function formatMitigationBlock(mitigation: MitigationRecord): string {
  const parts = [
    "#### Suggested fix",
    "",
    `**${mitigation.title}** _(effort: ${mitigation.effort})_`,
    "",
    mitigation.description,
  ];

  if (mitigation.suggestedPatch) {
    const patch = mitigation.suggestedPatch.trim();
    const fence = patch.startsWith("@@") || patch.startsWith("---") ? "diff" : "";
    parts.push("", "```" + fence, patch, "```");
  }

  if (mitigation.alternativeApproaches.length > 0) {
    parts.push("", "**Alternatives:**");
    for (const alt of mitigation.alternativeApproaches) {
      parts.push(`- ${alt}`);
    }
  }

  if (mitigation.references.length > 0) {
    parts.push("", "**References:**");
    for (const ref of mitigation.references) {
      parts.push(`- ${ref}`);
    }
  }

  return parts.join("\n");
}

export function formatFindingWithMitigation(item: ReviewCommentItem): string {
  return [formatFindingBlock(item.finding), "", formatMitigationBlock(item.mitigation)].join(
    "\n"
  );
}

export function formatSummaryReviewComment(input: {
  reviewId: string;
  items: ReviewCommentItem[];
  reviewUrl?: string;
}): string {
  const { reviewId, items, reviewUrl } = input;
  const lines = [
    "## SecAgent security review",
    "",
    `Found **${items.length}** issue${items.length === 1 ? "" : "s"} with suggested fixes.`,
    "",
  ];

  if (items.length === 0) {
    lines.push("No security issues detected in this diff.");
  } else {
    lines.push("| Severity | Category | Location | Issue | Fix effort |");
    lines.push("|----------|----------|----------|-------|------------|");
    for (const { finding, mitigation } of items) {
      const emoji = SEVERITY_EMOJI[finding.severity] ?? "";
      lines.push(
        `| ${emoji} ${finding.severity} | ${finding.category} | ${formatLocation(finding)} | ${finding.title} | ${mitigation.effort} |`
      );
    }
    lines.push("");
    for (const item of items) {
      lines.push(formatFindingWithMitigation(item), "", "---", "");
    }
  }

  const link = reviewUrl ?? `https://secagent.internal/reviews/${reviewId}`;
  lines.push(
    `<sub>Review id: \`${reviewId.slice(0, 8)}…\` · [Open findings](${link}) · Powered by SecAgent</sub>`
  );
  return lines.join("\n");
}

export function buildReviewComments(input: {
  reviewId: string;
  items: ReviewCommentItem[];
  reviewUrl?: string;
  /** When true, emit per-finding inline comments where file+line are known. */
  inline?: boolean;
}): GitHubReviewComment[] {
  const summary: GitHubReviewComment = {
    body: formatSummaryReviewComment({
      reviewId: input.reviewId,
      items: input.items,
      reviewUrl: input.reviewUrl,
    }),
  };

  if (!input.inline) {
    return [summary];
  }

  const inlineComments: GitHubReviewComment[] = [];
  for (const item of input.items) {
    const { finding } = item;
    if (!finding.filePath) continue;

    const comment: GitHubReviewComment = {
      path: finding.filePath,
      side: "RIGHT",
      body: formatFindingWithMitigation(item),
    };

    if (finding.lineStart !== undefined) {
      comment.line = finding.lineStart;
    }

    inlineComments.push(comment);
  }

  return inlineComments.length > 0 ? [summary, ...inlineComments] : [summary];
}
