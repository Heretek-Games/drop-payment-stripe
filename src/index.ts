import type {
  PaymentGateway,
  PaymentIntentRequest,
  PaymentIntentResult,
  PaymentWebhookResult,
  PluginContext,
  ServerPlugin,
} from "@droposs/plugin-sdk";

const API_BASE = "https://api.stripe.com/v1";

export interface HttpRequest {
  (url: string, init?: RequestInit): Promise<Response>;
}

/** Stripe gateway adapter. */
export class StripeGateway implements PaymentGateway {
  id = "stripe";
  name = "Stripe";

  constructor(
    private readonly secretKey: string | undefined,
    private readonly fetchFn: HttpRequest,
  ) {}

  async createPaymentIntent(
    req: PaymentIntentRequest,
  ): Promise<PaymentIntentResult> {
    if (!this.secretKey) {
      throw new Error("Stripe secret key is not configured");
    }
    const response = await this.fetchFn(`${API_BASE}/payment_intents`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ orderId: req.orderId, amount: req.amount, currency: req.currency }),
    });
    if (!response.ok) {
      throw new Error(`Stripe checkout failed: ${response.status}`);
    }
    const payload = (await response.json()) as Record<string, unknown>;
    return {
      intentId: String(payload.id ?? req.orderId),
      clientSecret: payload.clientSecret ? String(payload.clientSecret) : undefined,
      checkoutUrl: payload.checkoutUrl ? String(payload.checkoutUrl) : undefined,
      status: "pending",
    };
  }

  async handleWebhook(
    payload: unknown,
    _headers: Record<string, string>,
  ): Promise<PaymentWebhookResult> {
    const body = (payload ?? {}) as Record<string, unknown>;
    return {
      orderId: String(body.orderId ?? body.metadata ?? ""),
      status: (body.status as PaymentWebhookResult["status"]) ?? "succeeded",
      transactionId: String(body.transactionId ?? body.id ?? ""),
      payload: body,
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
    ctx.registerPaymentGateway(
      new StripeGateway(secret, ctx.fetch.bind(ctx) as HttpRequest),
    );
    ctx.logger.info(
      `Stripe gateway registered${secret ? "" : " (no secret configured)"}`,
    );
  }
}
