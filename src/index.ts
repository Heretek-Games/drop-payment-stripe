import { createHmac, timingSafeEqual } from "node:crypto";
import type {
  PaymentGateway,
  PaymentIntentRequest,
  PaymentIntentResult,
  PaymentWebhookResult,
  PluginContext,
  ServerPlugin,
} from "@droposs/plugin-sdk";

const API_BASE = "https://api.stripe.com/v1";

/** Stripe's default webhook replay tolerance (5 minutes). */
export const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300;

export interface HttpRequest {
  (url: string, init?: RequestInit): Promise<Response>;
}

/** Thrown when a Stripe webhook cannot be authenticated. */
export class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebhookVerificationError";
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

function headerValue(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() === target) return value;
  }
  return undefined;
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[0-9a-f]+$/i.test(left) || !/^[0-9a-f]+$/i.test(right)) return false;
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  if (leftBytes.length === 0 || leftBytes.length !== rightBytes.length) {
    return false;
  }
  return timingSafeEqual(leftBytes, rightBytes);
}

/**
 * Stripe signs the raw request body, so verification is only meaningful when
 * the host hands `handleWebhook` the untouched body. Strings and byte arrays
 * are used verbatim; anything else is re-serialized as a best effort and may
 * not match Stripe's signature.
 */
function toRawBody(payload: unknown): string {
  if (typeof payload === "string") return payload;
  if (payload instanceof Uint8Array) return new TextDecoder().decode(payload);
  if (payload instanceof ArrayBuffer) {
    return new TextDecoder().decode(new Uint8Array(payload));
  }
  return JSON.stringify(payload ?? {});
}

export interface StripeSignatureParts {
  timestamp?: number;
  signatures: string[];
}

/** Parse a `Stripe-Signature` header (`t=...,v1=...[,v1=...]`). */
export function parseStripeSignatureHeader(header: string): StripeSignatureParts {
  const parts: StripeSignatureParts = { signatures: [] };
  for (const item of header.split(",")) {
    const separator = item.indexOf("=");
    if (separator < 0) continue;
    const key = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    if (key === "t") {
      const timestamp = Number.parseInt(value, 10);
      if (Number.isFinite(timestamp) && timestamp >= 0) {
        parts.timestamp = timestamp;
      }
    } else if (key === "v1" && value.length > 0) {
      parts.signatures.push(value);
    }
  }
  return parts;
}

export interface VerifyStripeSignatureOptions {
  rawBody: string;
  signatureHeader: string | undefined;
  secret: string;
  /** Replay tolerance in seconds; defaults to 300 (Stripe's own default). */
  toleranceSeconds?: number;
  /** Current unix time in seconds; injectable for tests. */
  nowSeconds?: number;
}

/**
 * Verify a Stripe webhook signature: HMAC-SHA256 over `${timestamp}.${payload}`
 * with the endpoint secret, in constant time, rejecting timestamps outside the
 * tolerance window. Fails closed when no secret is configured.
 */
export function verifyStripeSignature(
  options: VerifyStripeSignatureOptions,
): void {
  const { rawBody, signatureHeader, secret } = options;
  if (secret.length === 0) {
    throw new WebhookVerificationError(
      "Stripe webhook secret is not configured",
    );
  }
  if (!signatureHeader) {
    throw new WebhookVerificationError("Missing Stripe-Signature header");
  }
  const { timestamp, signatures } = parseStripeSignatureHeader(signatureHeader);
  if (timestamp === undefined) {
    throw new WebhookVerificationError(
      "Stripe-Signature header is missing the timestamp",
    );
  }
  if (signatures.length === 0) {
    throw new WebhookVerificationError(
      "Stripe-Signature header is missing a v1 signature",
    );
  }
  const tolerance =
    options.toleranceSeconds ?? DEFAULT_WEBHOOK_TOLERANCE_SECONDS;
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > tolerance) {
    throw new WebhookVerificationError(
      "Stripe webhook timestamp is outside the tolerance window",
    );
  }
  const expected = createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`, "utf8")
    .digest("hex");
  if (!signatures.some((signature) => safeEqualHex(signature, expected))) {
    throw new WebhookVerificationError(
      "Stripe webhook signature verification failed",
    );
  }
}

function mapIntentStatus(status: unknown): PaymentIntentResult["status"] {
  switch (status) {
    case "succeeded":
      return "succeeded";
    case "canceled":
      return "failed";
    default:
      return "pending";
  }
}

function mapEventStatus(
  type: string | undefined,
  object: Record<string, unknown>,
): PaymentWebhookResult["status"] {
  switch (type) {
    case "payment_intent.succeeded":
    case "charge.succeeded":
      return "succeeded";
    case "payment_intent.payment_failed":
    case "payment_intent.canceled":
    case "charge.failed":
      return "failed";
    case "charge.refunded":
      return "refunded";
    default:
      break;
  }
  switch (firstString(object["status"])) {
    case "succeeded":
      return "succeeded";
    case "failed":
    case "canceled":
      return "failed";
    case "refunded":
      return "refunded";
    default:
      throw new Error(
        `Unsupported Stripe webhook event type: ${type ?? "unknown"}`,
      );
  }
}

/** Stripe gateway adapter. */
export class StripeGateway implements PaymentGateway {
  id = "stripe";
  name = "Stripe";

  constructor(
    private readonly secretKey: string | undefined,
    private readonly fetchFn: HttpRequest,
    private readonly webhookSecret?: string,
    private readonly webhookToleranceSeconds: number = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
  ) {}

  async createPaymentIntent(
    req: PaymentIntentRequest,
  ): Promise<PaymentIntentResult> {
    if (!this.secretKey) {
      throw new Error("Stripe secret key is not configured");
    }
    const body = new URLSearchParams();
    body.set("amount", String(req.amount));
    body.set("currency", req.currency.toLowerCase());
    body.set("metadata[orderId]", req.orderId);
    if (req.customerEmail) {
      body.set("receipt_email", req.customerEmail);
    }
    for (const [key, value] of Object.entries(req.metadata ?? {})) {
      if (value === undefined || value === null) continue;
      body.set(
        `metadata[${key}]`,
        typeof value === "string" ? value : JSON.stringify(value),
      );
    }
    const response = await this.fetchFn(`${API_BASE}/payment_intents`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });
    if (!response.ok) {
      throw new Error(`Stripe checkout failed: ${response.status}`);
    }
    const payload = (await response.json()) as Record<string, unknown>;
    const nextAction = asRecord(payload["next_action"]);
    const redirectToUrl = asRecord(nextAction?.["redirect_to_url"]);
    return {
      intentId: String(payload["id"] ?? req.orderId),
      clientSecret: firstString(payload["client_secret"], payload["clientSecret"]),
      checkoutUrl: firstString(
        payload["checkout_url"],
        redirectToUrl?.["url"],
      ),
      status: mapIntentStatus(payload["status"]),
    };
  }

  async handleWebhook(
    payload: unknown,
    headers: Record<string, string>,
  ): Promise<PaymentWebhookResult> {
    const rawBody = toRawBody(payload);
    verifyStripeSignature({
      rawBody,
      signatureHeader: headerValue(headers, "stripe-signature"),
      secret: this.webhookSecret ?? "",
      toleranceSeconds: this.webhookToleranceSeconds,
    });
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(rawBody) as Record<string, unknown>;
    } catch {
      throw new WebhookVerificationError("Malformed Stripe webhook payload");
    }
    const data = asRecord(event["data"]);
    const object = asRecord(data?.["object"]) ?? event;
    const metadata = asRecord(object["metadata"]) ?? {};
    return {
      orderId:
        firstString(
          metadata["orderId"],
          metadata["order_id"],
          object["orderId"],
          event["orderId"],
        ) ?? "",
      status: mapEventStatus(firstString(event["type"]), object),
      transactionId:
        firstString(
          object["latest_charge"],
          object["charge"],
          object["id"],
          event["id"],
        ) ?? "",
      payload: object,
    };
  }
}

export default class StripePlugin implements ServerPlugin {
  metadata = {
    id: "drop-payment-stripe",
    name: "Stripe",
    version: "0.1.0",
    apiVersion: 2,
    capabilities: ["commerce:payment" as const, "network" as const],
  };

  async init(ctx: PluginContext): Promise<void> {
    const secret = process.env["STRIPE_SECRET_KEY"];
    const webhookSecret = process.env["STRIPE_WEBHOOK_SECRET"];
    ctx.registerPaymentGateway(
      new StripeGateway(
        secret,
        ctx.fetch.bind(ctx) as HttpRequest,
        webhookSecret,
      ),
    );
    ctx.logger.info(
      `Stripe gateway registered${secret ? "" : " (no secret configured)"}`,
    );
    if (!webhookSecret) {
      ctx.logger.warn(
        "Stripe webhook secret is not configured; webhook calls will be rejected",
      );
    }
  }
}
