import { randomBytes } from "node:crypto";
import type { TelemetryEventRecord } from "./types.js";

export interface OtelBridgeOptions {
  endpoint?: string;
  serviceName?: string;
  fetchImpl?: typeof fetch;
}

/**
 * Lightweight OTLP-ish bridge: logs span-shaped JSON when endpoint is set.
 * Full @opentelemetry/sdk wiring can replace this without changing call sites.
 */
export class OtelBridge {
  private readonly endpoint?: string;
  private readonly serviceName: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: OtelBridgeOptions = {}) {
    this.endpoint = options.endpoint?.replace(/\/$/, "");
    this.serviceName = options.serviceName ?? "li-sec-agent";
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  enabled(): boolean {
    return Boolean(this.endpoint);
  }

  startSpan(name: string): { traceId: string; spanId: string; end: (attrs?: Record<string, unknown>) => void } {
    const traceId = randomBytes(16).toString("hex");
    const spanId = randomBytes(8).toString("hex");
    const started = Date.now();

    return {
      traceId,
      spanId,
      end: (attrs = {}) => {
        void this.exportSpan({
          traceId,
          spanId,
          name,
          durationMs: Date.now() - started,
          attributes: attrs,
        });
      },
    };
  }

  async recordEvent(event: TelemetryEventRecord): Promise<void> {
    if (!this.endpoint) return;
    const span = this.startSpan(event.eventType);
    span.end({
      "secagent.review_id": event.reviewId,
      "secagent.org_id": event.orgId,
      "secagent.event_type": event.eventType,
    });
  }

  private async exportSpan(input: {
    traceId: string;
    spanId: string;
    name: string;
    durationMs: number;
    attributes: Record<string, unknown>;
  }): Promise<void> {
    if (!this.endpoint) return;
    const body = {
      resourceSpans: [
        {
          resource: { attributes: [{ key: "service.name", value: { stringValue: this.serviceName } }] },
          scopeSpans: [
            {
              spans: [
                {
                  traceId: input.traceId,
                  spanId: input.spanId,
                  name: input.name,
                  startTimeUnixNano: String((Date.now() - input.durationMs) * 1_000_000),
                  endTimeUnixNano: String(Date.now() * 1_000_000),
                  attributes: Object.entries(input.attributes).map(([key, value]) => ({
                    key,
                    value: { stringValue: String(value) },
                  })),
                },
              ],
            },
          ],
        },
      ],
    };

    try {
      await this.fetchImpl(`${this.endpoint}/v1/traces`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch {
      // Exporter failures must not break reviews
    }
  }
}
