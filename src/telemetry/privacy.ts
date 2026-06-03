import { createHash } from "node:crypto";

const SECRET_PATTERNS: RegExp[] = [
  /(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*['"]?[^\s'"]+/gi,
  /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/g,
  /ghp_[A-Za-z0-9]{20,}/g,
  /github_pat_[A-Za-z0-9_]+/g,
  /sk-[A-Za-z0-9]{20,}/g,
  /Bearer\s+[A-Za-z0-9._-]+/gi,
];

export function hashContent(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** Redact likely secrets before persistence or OTLP export. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, "[REDACTED]");
  }
  return out;
}

export function safePayload(payload: Record<string, unknown>): string {
  return JSON.stringify(
    JSON.parse(redactSecrets(JSON.stringify(payload)))
  );
}

export function countDiffLines(diffText: string): number {
  if (!diffText) return 0;
  return diffText.split("\n").filter((line) => line.startsWith("+") || line.startsWith("-")).length;
}
