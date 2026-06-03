/**
 * Security PR review model benchmark against in-cluster Ollama (OpenAI-compatible API).
 *
 * Usage:
 *   npx tsx scripts/eval-models.ts
 *   QWEN_BASE_URL=http://192.168.10.33:31434/v1 MODELS=qwen2.5-coder:3b,qwen3.5:9b npx tsx scripts/eval-models.ts
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");

const SECURITY_SYSTEM_PROMPT = `You are a security-focused code reviewer.
Analyze the pull request diff for vulnerabilities (injection, authz, secrets, crypto, unsafe dependencies).
Respond with a JSON array only. Each item: { "severity", "category", "title", "detail", "file_path", "line_start" }.
severity: info|low|medium|high|critical. category: injection|authz|secrets|crypto|dependency|config|other.
If no issues, return [].`;

type BenchmarkCase = {
  id: string;
  file_path: string;
  diff: string;
  expected: Array<{ category: string }>;
  negative: boolean;
  language?: string;
  category?: string;
  cwe?: string;
};

type RawFinding = {
  severity?: string;
  category?: string;
  title?: string;
  detail?: string;
  file_path?: string;
  line_start?: number;
};

type CaseResult = {
  caseId: string;
  negative: boolean;
  expectedCategories: string[];
  predictedCategories: string[];
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  parseOk: boolean;
  rawResponsePreview: string;
};

type ModelResult = {
  model: string;
  status: "ok" | "error" | "oom";
  error?: string;
  cases: CaseResult[];
  latencyMs: { p50: number; p95: number; mean: number; total: number };
  tokens: { prompt: number; completion: number; total: number };
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  negativeCasePassRate: number;
  vramUsedMiB?: number;
  vramTotalMiB?: number;
  evaluatedAt: string;
};

function parseFindingsJson(text: string): RawFinding[] {
  const trimmed = text.trim();
  const jsonBlock = trimmed.match(/```json\s*([\s\S]*?)```/i)?.[1] ?? trimmed;
  const arrayMatch = jsonBlock.match(/\[[\s\S]*\]/);
  const candidate = arrayMatch?.[0] ?? jsonBlock;
  try {
    const data = JSON.parse(candidate) as unknown;
    return Array.isArray(data) ? (data as RawFinding[]) : [];
  } catch {
    return [];
  }
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[idx] ?? 0;
}

function scoreCase(
  testCase: BenchmarkCase,
  findings: RawFinding[],
  parseOk: boolean
): CaseResult {
  const predicted = [...new Set(findings.map((f) => (f.category ?? "other").toLowerCase()))];
  const expected = testCase.expected.map((e) => e.category.toLowerCase());

  if (testCase.negative) {
    const fp = findings.length;
    return {
      caseId: testCase.id,
      negative: true,
      expectedCategories: [],
      predictedCategories: predicted,
      truePositives: 0,
      falsePositives: fp,
      falseNegatives: 0,
      parseOk,
      rawResponsePreview: "",
    };
  }

  const matched = expected.filter((cat) => predicted.includes(cat));
  return {
    caseId: testCase.id,
    negative: false,
    expectedCategories: expected,
    predictedCategories: predicted,
    truePositives: matched.length,
    falsePositives: Math.max(0, predicted.length - matched.length),
    falseNegatives: expected.length - matched.length,
    parseOk,
    rawResponsePreview: "",
  };
}

async function fetchVram(baseUrl: string): Promise<{ used?: number; total?: number }> {
  const root = baseUrl.replace(/\/v1$/, "");
  try {
    const response = await fetch(`${root}/api/ps`);
    if (!response.ok) return {};
    const payload = (await response.json()) as {
      models?: Array<{ size_vram?: number }>;
    };
    const usedBytes = (payload.models ?? []).reduce(
      (sum, m) => sum + (m.size_vram ?? 0),
      0
    );
    return { used: Math.round(usedBytes / (1024 * 1024)) };
  } catch {
    return {};
  }
}


async function chatCompletion(
  baseUrl: string,
  apiKey: string,
  body: Record<string, unknown>,
  requestTimeoutMs: number,
  maxAttempts = 4
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        signal: AbortSignal.timeout(requestTimeoutMs),
        body: JSON.stringify(body),
      });
      return response;
    } catch (error) {
      lastError = error;
      const message = error instanceof Error ? error.message : String(error);
      const retryable =
        message.includes("fetch failed") ||
        message.includes("ECONNRESET") ||
        message.includes("ETIMEDOUT") ||
        message.includes("socket");
      if (!retryable || attempt === maxAttempts) throw error;
      await new Promise((r) => setTimeout(r, 2000 * attempt));
    }
  }
  throw lastError;
}
async function runModel(
  baseUrl: string,
  apiKey: string,
  model: string,
  cases: BenchmarkCase[]
): Promise<ModelResult> {
  const requestTimeoutMs = Number(process.env.REQUEST_TIMEOUT_MS ?? "600000");
  const latencies: number[] = [];
  let promptTokens = 0;
  let completionTokens = 0;
  const caseResults: CaseResult[] = [];

  for (const testCase of cases) {
    const started = Date.now();
    try {
      const response = await chatCompletion(baseUrl, apiKey, {
          model,
          messages: [
            { role: "system", content: SECURITY_SYSTEM_PROMPT },
            {
              role: "user",
              content: [
                "Repository: li-langverse/eval-fixtures",
                "PR: #1",
                "Diff:",
                `--- a/${testCase.file_path}`,
                `+++ b/${testCase.file_path}`,
                testCase.diff,
              ].join("\n"),
            },
          ],
          temperature: 0.1,
          stream: false,
          ...(process.env.OLLAMA_NUM_CTX
            ? { options: { num_ctx: Number(process.env.OLLAMA_NUM_CTX) } }
            : {}),
        }, requestTimeoutMs);

      const latencyMs = Date.now() - started;
      latencies.push(latencyMs);

      if (!response.ok) {
        const body = await response.text();
        const isOom =
          body.includes("CUDA out of memory") ||
          body.includes("out of memory") ||
          body.includes("requires more system memory");
        return {
          model,
          status: isOom ? "oom" : "error",
          error: `HTTP ${response.status}: ${body.slice(0, 500)}`,
          cases: caseResults,
          latencyMs: { p50: 0, p95: 0, mean: 0, total: 0 },
          tokens: { prompt: 0, completion: 0, total: 0 },
          precision: 0,
          recall: 0,
          f1: 0,
          falsePositiveRate: 0,
          negativeCasePassRate: 0,
          evaluatedAt: new Date().toISOString(),
        };
      }

      const payload = (await response.json()) as {
        usage?: { prompt_tokens?: number; completion_tokens?: number };
        choices?: Array<{ message?: { content?: string } }>;
      };

      promptTokens += payload.usage?.prompt_tokens ?? 0;
      completionTokens += payload.usage?.completion_tokens ?? 0;

      const content = payload.choices?.[0]?.message?.content ?? "";
      const findings = parseFindingsJson(content);
      const scored = scoreCase(testCase, findings, content.trim().length > 0);
      scored.rawResponsePreview = content.slice(0, 240).replace(/\s+/g, " ");
      caseResults.push(scored);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const isOom = message.toLowerCase().includes("out of memory");
      return {
        model,
        status: isOom ? "oom" : "error",
        error: message,
        cases: caseResults,
        latencyMs: { p50: 0, p95: 0, mean: 0, total: 0 },
        tokens: { prompt: 0, completion: 0, total: 0 },
        precision: 0,
        recall: 0,
        f1: 0,
        falsePositiveRate: 0,
        negativeCasePassRate: 0,
        evaluatedAt: new Date().toISOString(),
      };
    }
  }

  const tp = caseResults.reduce((s, c) => s + c.truePositives, 0);
  const fp = caseResults.reduce((s, c) => s + c.falsePositives, 0);
  const fn = caseResults.reduce((s, c) => s + c.falseNegatives, 0);
  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  const negativeCases = caseResults.filter((c) => c.negative);
  const negativePassed = negativeCases.filter((c) => c.falsePositives === 0).length;
  const falsePositiveRate =
    negativeCases.length > 0
      ? 1 - negativePassed / negativeCases.length
      : 0;

  const vram = await fetchVram(baseUrl);

  return {
    model,
    status: "ok",
    cases: caseResults,
    latencyMs: {
      p50: percentile(latencies, 50),
      p95: percentile(latencies, 95),
      mean: latencies.length
        ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
        : 0,
      total: latencies.reduce((a, b) => a + b, 0),
    },
    tokens: {
      prompt: promptTokens,
      completion: completionTokens,
      total: promptTokens + completionTokens,
    },
    precision: round(precision),
    recall: round(recall),
    f1: round(f1),
    falsePositiveRate: round(falsePositiveRate),
    negativeCasePassRate: round(
      negativeCases.length > 0 ? negativePassed / negativeCases.length : 1
    ),
    vramUsedMiB: vram.used,
    evaluatedAt: new Date().toISOString(),
  };
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}

function printSummary(results: ModelResult[]): void {
  console.log("\n| Model | Status | F1 | Prec | Recall | FP rate | Neg pass | p50 ms | VRAM MiB |");
  console.log("|-------|--------|-----|------|--------|---------|----------|--------|----------|");
  for (const r of results) {
    console.log(
      `| ${r.model} | ${r.status} | ${r.f1} | ${r.precision} | ${r.recall} | ${r.falsePositiveRate} | ${r.negativeCasePassRate} | ${r.latencyMs.p50} | ${r.vramUsedMiB ?? "n/a"} |`
    );
    if (r.error) console.log(`  error: ${r.error.slice(0, 120)}`);
  }
}

async function main(): Promise<void> {
  const baseUrl =
    process.env.QWEN_BASE_URL ?? "http://192.168.10.33:31434/v1";
  const apiKey = process.env.QWEN_API_KEY ?? "ollama";
  const models = (
    process.env.MODELS ??
    "qwen2.5-coder:3b,qwen3.5:9b,qwen3:14b,qwen3.5:27b"
  )
    .split(",")
    .map((m) => m.trim())
    .filter(Boolean);

  const legacyPath = join(REPO_ROOT, "eval", "benchmark-cases.json");
  const defaultMultilang = join(REPO_ROOT, "eval", "benchmark-multilang.json");
  const multilangPath = process.env.BENCHMARK_PATH
    ? join(REPO_ROOT, process.env.BENCHMARK_PATH)
    : defaultMultilang;
  const mode = (process.env.BENCHMARK_MODE ?? "single").toLowerCase();

  let cases: BenchmarkCase[] = [];
  if (mode === "combined") {
    const legacy = JSON.parse(readFileSync(legacyPath, "utf8")) as BenchmarkCase[];
    const multi = JSON.parse(readFileSync(multilangPath, "utf8")) as BenchmarkCase[];
    const seen = new Set<string>();
    cases = [...legacy, ...multi].filter((c) => {
      if (seen.has(c.id)) return false;
      seen.add(c.id);
      return true;
    });
    console.log(`Benchmark mode: combined (${legacy.length} legacy + ${multi.length} multilang -> ${cases.length})`);
  } else if (process.env.BENCHMARK_PATH) {
    cases = JSON.parse(readFileSync(multilangPath, "utf8")) as BenchmarkCase[];
    console.log(`Benchmark file: ${multilangPath}`);
  } else {
    cases = JSON.parse(readFileSync(legacyPath, "utf8")) as BenchmarkCase[];
    console.log(`Benchmark file: ${legacyPath}`);
  }

  const caseLimit = Number(process.env.CASE_LIMIT ?? "0");
  if (caseLimit > 0) {
    cases = cases.slice(0, caseLimit);
    console.log(`CASE_LIMIT=${caseLimit} (subset for smoke)`);
  }


  const caseIds = (process.env.CASE_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (caseIds.length > 0) {
    cases = cases.filter((c) => caseIds.includes(c.id));
    console.log(`CASE_IDS filter: ${cases.length} cases`);
  }
  const resultsDir = join(REPO_ROOT, "eval", "results");
  mkdirSync(resultsDir, { recursive: true });

  console.log(`Benchmark: ${cases.length} cases, API ${baseUrl}`);
  console.log(`Models: ${models.join(", ")}`);

  const results: ModelResult[] = [];
  for (const model of models) {
    console.log(`\n==> Evaluating ${model}...`);
    const result = await runModel(baseUrl, apiKey, model, cases);
    results.push(result);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const outFile = join(resultsDir, `${model.replace(/[:/]/g, "_")}-${stamp}.json`);
    writeFileSync(outFile, JSON.stringify(result, null, 2));
    console.log(`Wrote ${outFile}`);
  }

  const summaryPath = join(resultsDir, `summary-${Date.now()}.json`);
  writeFileSync(summaryPath, JSON.stringify({ baseUrl, models, results }, null, 2));
  printSummary(results);
  console.log(`\nSummary: ${summaryPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
