import { hashContent, redactSecrets } from "../telemetry/privacy.js";
import type { TelemetryPipeline } from "../telemetry/pipeline.js";

export interface QwenChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface QwenCompletionResult {
  content: string;
  model: string;
  promptTokens?: number;
  completionTokens?: number;
  latencyMs: number;
  promptHash: string;
  responseHash: string;
}

export interface QwenClientOptions {
  baseUrl: string;
  model: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
  telemetry?: TelemetryPipeline;
}

/**
 * OpenAI-compatible client for in-cluster Qwen (Ollama / vLLM).
 */
export class QwenClient {
  private readonly baseUrl: string;
  private readonly model: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;
  private readonly telemetry?: TelemetryPipeline;

  constructor(options: QwenClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.model = options.model;
    this.apiKey = options.apiKey ?? "ollama";
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.telemetry = options.telemetry;
  }

  async complete(
    messages: QwenChatMessage[],
    meta: { reviewId: string; repoFullName?: string; prNumber?: number }
  ): Promise<QwenCompletionResult> {
    const promptText = messages.map((m) => `${m.role}: ${m.content}`).join("\n");
    this.telemetry?.emit({
      eventType: "qwen_inference_started",
      reviewId: meta.reviewId,
      repoFullName: meta.repoFullName,
      prNumber: meta.prNumber,
      modelId: this.model,
      promptHash: hashContent(promptText),
    });

    const started = Date.now();
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: this.model,
          messages,
          temperature: 0.1,
          stream: false,
        }),
      });

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`Qwen request failed (${response.status}): ${body}`);
      }

      const payload = (await response.json()) as {
        model?: string;
        usage?: { prompt_tokens?: number; completion_tokens?: number };
        choices?: Array<{ message?: { content?: string } }>;
      };

      const content = payload.choices?.[0]?.message?.content?.trim();
      if (!content) {
        throw new Error("Qwen returned empty completion");
      }

      const result: QwenCompletionResult = {
        content,
        model: payload.model ?? this.model,
        promptTokens: payload.usage?.prompt_tokens,
        completionTokens: payload.usage?.completion_tokens,
        latencyMs: Date.now() - started,
        promptHash: hashContent(promptText),
        responseHash: hashContent(content),
      };

      this.telemetry?.emit({
        eventType: "qwen_inference_completed",
        reviewId: meta.reviewId,
        repoFullName: meta.repoFullName,
        prNumber: meta.prNumber,
        modelId: result.model,
        promptHash: result.promptHash,
        responseHash: result.responseHash,
        tokensIn: result.promptTokens,
        tokensOut: result.completionTokens,
        latencyMs: result.latencyMs,
      });

      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.telemetry?.emit({
        eventType: "qwen_inference_failed",
        reviewId: meta.reviewId,
        repoFullName: meta.repoFullName,
        prNumber: meta.prNumber,
        modelId: this.model,
        errorCode: "qwen_request_error",
        errorMessage: redactSecrets(message),
        latencyMs: Date.now() - started,
      });
      throw error;
    }
  }

  async health(): Promise<boolean> {
    try {
      const root = this.baseUrl.replace(/\/v1$/, "");
      const response = await this.fetchImpl(`${root}/api/tags`, {
        method: "GET",
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}
