import "dotenv/config";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { QwenClient } from "./llm/qwen-client.js";
import {
  CompositeScanner,
  QwenSecurityScanner,
  StaticScannerStub,
} from "./orchestrator/scanner.js";
import {
  createSqliteStore,
  hashText,
  scanIssuesToRecords,
} from "./data/store.js";
import {
  createGitHubWebhookRouter,
  type GitHubPullRequestPayload,
  type GitHubWebhookHandler,
} from "./webhooks/github.js";
import type { PullRequestContext } from "./types.js";
import {
  createOtelBridge,
  loadTelemetryContext,
  TelemetryPipeline,
} from "./telemetry/pipeline.js";
import { countDiffLines } from "./telemetry/privacy.js";
import { buildReviewComments } from "./pr-comment.js";

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
  model: process.env.QWEN_MODEL ?? "qwen3.5:9b",
  apiKey: process.env.QWEN_API_KEY,
  telemetry,
});

const scanner = new CompositeScanner([
  new StaticScannerStub(telemetry),
  new QwenSecurityScanner(qwen, store, telemetry),
]);

async function fetchDiffStub(payload: GitHubPullRequestPayload): Promise<string> {
  return `[stub] fetch diff from ${payload.pull_request.diff_url ?? "github api"}`;
}

async function postReviewComments(
  context: PullRequestContext,
  reviewId: string,
  items: ReturnType<typeof scanIssuesToRecords>
): Promise<void> {
  const reviewUrl =
    process.env.SECAGENT_REVIEW_URL?.replace("{reviewId}", reviewId) ??
    undefined;
  const inline = process.env.PR_INLINE_COMMENTS === "true";
  const comments = buildReviewComments({
    reviewId,
    items,
    reviewUrl,
    inline,
  });

  for (const comment of comments) {
    telemetry.emit({
      eventType: "pr_comment_posted",
      reviewId,
      repoFullName: context.repoFullName,
      prNumber: context.prNumber,
      findingsCount: items.length,
      mitigationCount: items.length,
      payload: {
        stub: !process.env.GITHUB_TOKEN,
        channel: "github_review_comment",
        inline: Boolean(comment.path),
        path: comment.path,
        line: comment.line,
        position: comment.position,
        body_length: comment.body.length,
      },
    });
  }

  if (process.env.GITHUB_TOKEN) {
    // Production: POST to GitHub Pull Request Review API (stub logs telemetry only for now).
    console.log(
      JSON.stringify({
        level: "info",
        msg: "github_review_comments_ready",
        review_id: reviewId,
        comment_count: comments.length,
      })
    );
  }
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
      const scanResults = await scanner.scan(context, review.id);
      const records = scanIssuesToRecords(review.id, scanResults);

      for (const { finding, mitigation } of records) {
        telemetry.emit({
          eventType: "finding_created",
          reviewId: review.id,
          findingId: finding.id,
          repoFullName: context.repoFullName,
          prNumber: context.prNumber,
          severity: finding.severity,
          category: finding.category,
          source: finding.source,
        });
        telemetry.emit({
          eventType: "mitigation_suggested",
          reviewId: review.id,
          findingId: finding.id,
          repoFullName: context.repoFullName,
          prNumber: context.prNumber,
          severity: finding.severity,
          category: finding.category,
          mitigationHash: mitigation.contentHash,
          mitigationCount: 1,
          payload: {
            effort: mitigation.effort,
            has_patch: Boolean(mitigation.suggestedPatch),
            references_count: mitigation.references.length,
          },
        });
      }

      store.saveScanResults(review.id, records);

      const tokensIn = records.reduce(
        (n, r) => n + (r.finding.promptTokens ?? 0),
        0
      );
      const tokensOut = records.reduce(
        (n, r) => n + (r.finding.completionTokens ?? 0),
        0
      );
      const staticCount = records.filter((r) => r.finding.source === "static")
        .length;
      const qwenCount = records.filter((r) => r.finding.source === "qwen")
        .length;

      telemetry.recordUsageMetering({
        reviewId: review.id,
        repoFullName: context.repoFullName,
        prNumber: context.prNumber,
        linesScanned: countDiffLines(diffText),
        tokensIn,
        tokensOut,
        findingsCount: records.length,
        staticFindings: staticCount,
        qwenFindings: qwenCount,
      });

      await postReviewComments(context, review.id, records);

      telemetry.emit({
        eventType: "review_completed",
        reviewId: review.id,
        repoFullName: context.repoFullName,
        prNumber: context.prNumber,
        findingsCount: records.length,
        mitigationCount: records.length,
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
      model: process.env.QWEN_MODEL ?? "qwen3.5:9b",
      otel: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? null,
      org_id: process.env.SECAGENT_ORG_ID ?? "homelab",
    })
  );
});
