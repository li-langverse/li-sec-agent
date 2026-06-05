import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseAndNormalizeScanResponse,
  parseScanResponse,
} from "./parse-scan-response.js";

const SAMPLE_QWEN_JSON = `[
  {
    "finding": {
      "severity": "high",
      "category": "injection",
      "cwe_id": "CWE-89",
      "title": "SQL injection via string concatenation",
      "detail": "User input is interpolated into SQL without escaping.",
      "file_path": "src/api/users.ts",
      "line_range": { "start": 42, "end": 44 },
      "evidence": "db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
      "confidence": 0.92
    },
    "mitigation": {
      "title": "Use parameterized queries",
      "description": "Replace string interpolation with bound parameters.",
      "suggested_patch": "await db.query('SELECT * FROM users WHERE id = $1', [req.params.id])",
      "references": [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
      ],
      "effort": "low",
      "alternative_approaches": ["Use an ORM with parameterized queries"]
    }
  },
  {
    "finding": {
      "severity": "critical",
      "category": "secrets",
      "cwe_id": "CWE-798",
      "title": "Hardcoded API key",
      "file_path": "src/config.ts",
      "line_range": { "start": 3 },
      "confidence": 0.98
    },
    "mitigation": {
      "title": "Externalize secret",
      "description": "Move key to environment variable and rotate.",
      "effort": "medium",
      "references": ["https://cwe.mitre.org/data/definitions/798.html"],
      "alternative_approaches": []
    }
  }
]`;

describe("parseScanResponse", () => {
  it("parses JSON array with finding+mitigation pairs", () => {
    const raw = parseScanResponse(SAMPLE_QWEN_JSON);
    assert.equal(raw.length, 2);
    assert.equal(raw[0].finding?.title, "SQL injection via string concatenation");
    assert.equal(raw[0].mitigation?.title, "Use parameterized queries");
  });

  it("parses fenced json blocks", () => {
    const fenced = "```json\n" + SAMPLE_QWEN_JSON + "\n```";
    const raw = parseScanResponse(fenced);
    assert.equal(raw.length, 2);
  });

  it("normalizes into ScanIssue records", () => {
    const issues = parseAndNormalizeScanResponse(SAMPLE_QWEN_JSON, {
      source: "qwen",
      modelId: "qwen3.5:9b",
    });
    assert.equal(issues.length, 2);

    const sqli = issues[0];
    assert.equal(sqli.finding.severity, "high");
    assert.equal(sqli.finding.cwe, "CWE-89");
    assert.equal(sqli.finding.lineStart, 42);
    assert.equal(sqli.finding.lineEnd, 44);
    assert.equal(sqli.finding.confidence, 0.92);
    assert.equal(sqli.mitigation.effort, "low");
    assert.equal(sqli.mitigation.references.length, 2);
    assert.ok(sqli.mitigation.suggestedPatch?.includes("$1"));

    const secret = issues[1];
    assert.equal(secret.finding.severity, "critical");
    assert.equal(secret.mitigation.effort, "medium");
  });

  it("returns empty array for invalid JSON", () => {
    assert.deepEqual(parseScanResponse("not json"), []);
  });
});
