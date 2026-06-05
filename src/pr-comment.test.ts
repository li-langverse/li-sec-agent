import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildReviewComments,
  formatFindingWithMitigation,
  formatSummaryReviewComment,
} from "./pr-comment.js";
import type { FindingRecord, MitigationRecord } from "./types.js";

const finding: FindingRecord = {
  id: "f1",
  reviewId: "r1",
  filePath: "src/auth.ts",
  lineStart: 42,
  lineEnd: 42,
  severity: "high",
  category: "secrets",
  title: "Hardcoded API key pattern",
  detail: "Literal secret in source may leak via VCS.",
  cwe: "CWE-798",
  evidence: 'const API_KEY = "sk-live-abc123";',
  confidence: 0.95,
  source: "qwen",
};

const mitigation: MitigationRecord = {
  id: "m1",
  findingId: "f1",
  title: "Move secret to environment variable",
  description:
    "Load the key from process.env and rotate the exposed credential.",
  suggestedPatch:
    "const API_KEY = process.env.API_KEY;\nif (!API_KEY) throw new Error('API_KEY required');",
  references: [
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
  ],
  effort: "low",
  alternativeApproaches: ["Use a secret manager (Vault, AWS SM)"],
  contentHash: "abc123",
};

describe("pr-comment formatter", () => {
  it("formats finding with suggested fix block", () => {
    const md = formatFindingWithMitigation({ finding, mitigation });
    assert.match(md, /Hardcoded API key pattern/);
    assert.match(md, /#### Suggested fix/);
    assert.match(md, /Move secret to environment variable/);
    assert.match(md, /process\.env\.API_KEY/);
    assert.match(md, /CWE-798/);
    assert.match(md, /Alternatives/);
  });

  it("formats summary review comment with table", () => {
    const md = formatSummaryReviewComment({
      reviewId: "8b2e4f1a-0000-4000-8000-000000000001",
      items: [{ finding, mitigation }],
    });
    assert.match(md, /## SecAgent security review/);
    assert.match(md, /Found \*\*1\*\* issue/);
    assert.match(md, /\| 🟠 high \| secrets \|/);
    assert.match(md, /Suggested fix/);
  });

  it("builds inline comments when file+line present", () => {
    const comments = buildReviewComments({
      reviewId: "r1",
      items: [{ finding, mitigation }],
      inline: true,
    });
    assert.equal(comments.length, 2);
    assert.ok(!comments[0].path);
    assert.equal(comments[1].path, "src/auth.ts");
    assert.equal(comments[1].line, 42);
    assert.equal(comments[1].side, "RIGHT");
  });
});
