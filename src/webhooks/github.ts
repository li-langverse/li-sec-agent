import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { TelemetryPipeline } from "../telemetry/pipeline.js";

export type GitHubPullRequestAction = "opened" | "synchronize" | "reopened" | "ready_for_review";

export interface GitHubPullRequestPayload {
  action: GitHubPullRequestAction;
  number: number;
  pull_request: {
    number: number;
    head: { sha: string };
    base: { sha: string };
    diff_url?: string;
  };
  repository: { full_name: string };
  installation?: { id: number };
}

export interface GitHubWebhookHandler {
  onPullRequest(
    payload: GitHubPullRequestPayload,
    meta: { deliveryId: string; event: string; reviewId: string }
  ): Promise<void>;
}

export function verifyGitHubSignature(
  secret: string,
  rawBody: Buffer,
  signatureHeader: string | undefined
): boolean {
  if (!secret || !signatureHeader?.startsWith("sha256=")) {
    return false;
  }
  const expected = createHmac("sha256", secret).update(rawBody).digest("hex");
  const provided = signatureHeader.slice("sha256=".length);
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
  } catch {
    return false;
  }
}

export function createGitHubWebhookRouter(
  handler: GitHubWebhookHandler,
  telemetry?: TelemetryPipeline
) {
  const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET ?? "";

  return async function route(
    req: IncomingMessage,
    res: ServerResponse,
    rawBody: Buffer
  ): Promise<void> {
    if (req.method !== "POST" || req.url !== "/webhooks/github") {
      res.statusCode = 404;
      res.end("not found");
      return;
    }

    const event = req.headers["x-github-event"];
    const deliveryId = String(req.headers["x-github-delivery"] ?? "");
    const signature = req.headers["x-hub-signature-256"];

    if (webhookSecret && !verifyGitHubSignature(webhookSecret, rawBody, String(signature))) {
      res.statusCode = 401;
      res.end("invalid signature");
      return;
    }

    if (event !== "pull_request") {
      res.statusCode = 202;
      res.end("ignored");
      return;
    }

    const payload = JSON.parse(rawBody.toString("utf8")) as GitHubPullRequestPayload;
    const action = payload.action;
    if (!["opened", "synchronize", "reopened", "ready_for_review"].includes(action)) {
      res.statusCode = 202;
      res.end("ignored action");
      return;
    }

    const reviewId = randomUUID();
    telemetry?.emit({
      eventType: "pr_webhook_received",
      reviewId,
      deliveryId,
      repoFullName: payload.repository.full_name,
      prNumber: payload.number,
      commitSha: payload.pull_request.head.sha,
      payload: {
        action,
        installation_id: payload.installation?.id,
      },
    });

    await handler.onPullRequest(payload, {
      deliveryId,
      event: String(event),
      reviewId,
    });
    res.statusCode = 202;
    res.end("accepted");
  };
}
