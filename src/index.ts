import "dotenv/config";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { QwenClient } from "./llm/qwen-client.js";
import {
  CompositeScanner,
  QwenSecurityScanner,
  StaticScannerStub,
} from "./orchestrator/scanner.js";
import { createSqliteStore, hashText } from "./data/store.js";
import {
  createGitHubWebhookRouter,
  type GitHubPullRequestPayload,
  type GitHubWebhookHandler,
} from "./webhooks/github.js";
import type { FindingRecord, PullRequestContext } from "./types.js";
import {
  createOtelBridge,
  loadTelemetryContext,
  TelemetryPipeline,
} from "./telemetry/pipeline.js";
import { countDiffLines } from "./telemetry/privacy.js";

const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? "0.0.0.0";

const store = createSqliteStore(process.env.DATABASE_URL ?? "sqlite:./data/secagent.db");
const telemetry = new TelemetryPipeline({
  db: store.db,
  context: loadTelemetryContext(),
  otel: createOtelBridge(),
});

const qwen = new QwenClient({
  baseUrl: process.env.QWEN_BASE_URL ?? "http://127.0.0.1:11434/v1",
  model: process.env.QWEN_MODEL ?? "qwen2.5-coder:3b",
  apiKey: process.env.QWEN_API_KEY,
  telemetry,
});

const scanner = new CompositeScanner([
  new StaticScannerStub(telemetry),
  new QwenSecurityScanner(qwen, store),
]);

async function fetchDiffStub(payload: GitHubPullRequestPayload): Promise<string> {
  return `[stub] fetch diff from ${payload.pull_request.diff_url ?? "github api"}`;
}

async function postReviewCommentStub(
  context: PullRequestContext,
  reviewId: string,
  findingsCount: number
): Promise<void> {
  telemetry.emit({
    eventType: "pr_comment_posted",
    reviewId,
    repoFullName: context.repoFullName,
    prNumber: context.prNumber,
    findingsCount,
    payload: { stub: true, channel: "github_review_comment" },
  });
}

const webhookHandler: GitHubWebhookHandler = {
  async onPullRequest(payload, meta) {
    const reviewId = meta.reviewId;
    try {
      const diffText = await fetchDiffStub(payload);
      const context: PullRequestContext = {
        deliveryId: meta.deliveryId,
        repoFullName: payload.repository.full_name,
        prNumber: payload.number,
        headSha: payload.pull_request.head.sha,
        baseSha: payload.pull_request.base.sha,
        diffText,
        diffHash: hashText(diffText),
      };

      telemetry.emit({
        eventType: "diff_fetched",
        reviewId,
        deliveryId: meta.deliveryId,
        repoFullName: context.repoFullName,
        prNumber: context.prNumber,
        commitSha: context.headSha,
        diffHash: context.diffHash,
        linesScanned: countDiffLines(diffText),
      });

      const review = store.createReview(context);
      const results = await scanner.scan(context, review.id);
      const findings: FindingRecord[] = results.map((r) => {
        const id = randomUUID();
        telemetry.emit({
          eventType: "finding_created",
          reviewId: review.id,
          findingId: id,
          repoFullName: context.repoFullName,
          prNumber: context.prNumber,
          severity: r.finding.severity,
          category: r.finding.category,
          source: r.finding.source,
        });
        return { ...r.finding, id, reviewId: review.id };
      });
      store.saveFindings(review.id, findings);

      const tokensIn = findings.reduce((n, f) => n + (f.promptTokens ?? 0), 0);
      const tokensOut = findings.reduce((n, f) => n + (f.completionTokens ?? 0), 0);
      const staticCount = findings.filter((f) => f.source === "static").length;
      const qwenCount = findings.filter((f) => f.source === "qwen").length;

      telemetry.recordUsageMetering({
        reviewId: review.id,
        repoFullName: context.repoFullName,
        prNumber: context.prNumber,
        linesScanned: countDiffLines(diffText),
        tokensIn,
        tokensOut,
        findingsCount: findings.length,
        staticFindings: staticCount,
        qwenFindings: qwenCount,
      });

      await postReviewCommentStub(context, review.id, findings.length);

      telemetry.emit({
        eventType: "review_completed",
        reviewId: review.id,
        repoFullName: context.repoFullName,
        prNumber: context.prNumber,
        findingsCount: findings.length,
        linesScanned: countDiffLines(diffText),
        tokensIn,
        tokensOut,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      telemetry.emit({
        eventType: "review_failed",
        reviewId,
        repoFullName: payload.repository.full_name,
        prNumber: payload.number,
        errorCode: "review_pipeline_error",
        errorMessage: message,
      });
      throw error;
    }
  },
};

const githubRoute = createGitHubWebhookRouter(webhookHandler, telemetry);

const server = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const rawBody = Buffer.concat(chunks);

  if (req.url === "/healthz") {
    const qwenOk = await qwen.health();
    res.statusCode = qwenOk ? 200 : 503;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ ok: qwenOk, qwen: qwenOk, telemetry: true }));
    return;
  }

  if (req.url === "/readyz") {
    res.statusCode = 200;
    res.end("ok");
    return;
  }

  if (req.method === "POST" && req.url?.startsWith("/feedback/")) {
    const findingId = req.url.split("/feedback/")[1] ?? "";
    const body = JSON.parse(rawBody.toString("utf8")) as {
      review_id?: string;
      label?: string;
    };
    const reviewId = body.review_id ?? "unknown";
    const label = body.label ?? "thumbs_up";
    const eventType =
      label === "false_positive" ? "false_positive_labeled" : "user_feedback";
    telemetry.emit({
      eventType,
      reviewId,
      findingId,
      feedback: label as "thumbs_up",
    });
    res.statusCode = 202;
    res.end("accepted");
    return;
  }

  await githubRoute(req, res, rawBody);
});

server.listen(port, host, () => {
  console.log(
    JSON.stringify({
      level: "info",
      msg: "secagent_listening",
      host,
      port,
      qwen: process.env.QWEN_BASE_URL,
      otel: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? null,
      org_id: process.env.SECAGENT_ORG_ID ?? "homelab",
    })
  );
});
