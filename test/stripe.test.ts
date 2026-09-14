import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { MockPluginContext } from "@droposs/plugin-sdk";
import Plugin, {
  DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
  StripeGateway,
  WebhookVerificationError,
  parseStripeSignatureHeader,
  verifyStripeSignature,
} from "../src/index.js";
import type { HttpRequest } from "../src/index.js";

const WEBHOOK_SECRET = "whsec_test_secret";

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function signBody(rawBody: string, secret: string, timestamp: number): string {
  return createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`, "utf8")
    .digest("hex");
}

function signatureHeader(rawBody: string, timestamp = nowSeconds()): string {
  return `t=${timestamp},v1=${signBody(rawBody, WEBHOOK_SECRET, timestamp)}`;
}

function succeededEvent(orderId: string): string {
  return JSON.stringify({
    id: "evt_1",
    type: "payment_intent.succeeded",
    data: {
      object: {
        id: "pi_123",
        latest_charge: "ch_123",
        status: "succeeded",
        metadata: { orderId },
      },
    },
  });
}

test("drop-payment-stripe registers a payment gateway", async () => {
  const ctx = new MockPluginContext("drop-payment-stripe", ["commerce:payment", "network"]);
  await new Plugin().init(ctx);
  assert.equal(ctx.paymentGateways.size, 1);
  assert.equal(ctx.paymentGateways.get("stripe")?.name, "Stripe");
});

test("createPaymentIntent posts form-encoded data to Stripe", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fetchFn: HttpRequest = async (url, init) => {
    calls.push({ url, init });
    return new Response(
      JSON.stringify({
        id: "pi_123",
        client_secret: "pi_123_secret",
        status: "requires_payment_method",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };
  const gateway = new StripeGateway("sk_test_123", fetchFn);
  const result = await gateway.createPaymentIntent({
    orderId: "order-1",
    amount: 1999,
    currency: "USD",
    customerEmail: "buyer@example.com",
    metadata: { gameId: "g1" },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://api.stripe.com/v1/payment_intents");
  const headers = new Headers(calls[0].init?.headers);
  assert.equal(headers.get("content-type"), "application/x-www-form-urlencoded");
  assert.equal(headers.get("authorization"), "Bearer sk_test_123");
  const body = new URLSearchParams(String(calls[0].init?.body));
  assert.equal(body.get("amount"), "1999");
  assert.equal(body.get("currency"), "usd");
  assert.equal(body.get("metadata[orderId]"), "order-1");
  assert.equal(body.get("metadata[gameId]"), "g1");
  assert.equal(body.get("receipt_email"), "buyer@example.com");
  assert.deepEqual(result, {
    intentId: "pi_123",
    clientSecret: "pi_123_secret",
    checkoutUrl: undefined,
    status: "pending",
  });
});

test("createPaymentIntent maps Stripe status and redirect URL", async () => {
  const fetchFn: HttpRequest = async () =>
    new Response(
      JSON.stringify({
        id: "pi_9",
        client_secret: "secret",
        status: "requires_action",
        next_action: { redirect_to_url: { url: "https://pay.example/next" } },
      }),
      { status: 200 },
    );
  const gateway = new StripeGateway("sk", fetchFn);
  const result = await gateway.createPaymentIntent({
    orderId: "o",
    amount: 1,
    currency: "EUR",
  });
  assert.equal(result.status, "pending");
  assert.equal(result.checkoutUrl, "https://pay.example/next");
  assert.equal(result.clientSecret, "secret");
});

test("createPaymentIntent maps terminal Stripe statuses", async () => {
  const fetchFn = (status: string): HttpRequest => async () =>
    new Response(JSON.stringify({ id: "pi", status }), { status: 200 });
  assert.equal(
    (await new StripeGateway("sk", fetchFn("succeeded")).createPaymentIntent({
      orderId: "o",
      amount: 1,
      currency: "usd",
    })).status,
    "succeeded",
  );
  assert.equal(
    (await new StripeGateway("sk", fetchFn("canceled")).createPaymentIntent({
      orderId: "o",
      amount: 1,
      currency: "usd",
    })).status,
    "failed",
  );
});

test("createPaymentIntent fails without a secret key", async () => {
  const gateway = new StripeGateway(undefined, async () => new Response("{}"));
  await assert.rejects(
    gateway.createPaymentIntent({ orderId: "o", amount: 1, currency: "usd" }),
    /secret key is not configured/,
  );
});

test("createPaymentIntent surfaces Stripe API errors", async () => {
  const gateway = new StripeGateway("sk", async () => new Response("nope", { status: 402 }));
  await assert.rejects(
    gateway.createPaymentIntent({ orderId: "o", amount: 1, currency: "usd" }),
    /Stripe checkout failed: 402/,
  );
});

test("parseStripeSignatureHeader extracts timestamp and v1 signatures", () => {
  assert.deepEqual(parseStripeSignatureHeader("t=123,v1=abc,v1=def"), {
    timestamp: 123,
    signatures: ["abc", "def"],
  });
  assert.deepEqual(parseStripeSignatureHeader("garbage"), { signatures: [] });
});

test("verifyStripeSignature accepts a valid signature", () => {
  const rawBody = succeededEvent("order-1");
  assert.doesNotThrow(() =>
    verifyStripeSignature({
      rawBody,
      signatureHeader: signatureHeader(rawBody),
      secret: WEBHOOK_SECRET,
    }),
  );
});

test("verifyStripeSignature rejects an invalid signature", () => {
  const rawBody = succeededEvent("order-1");
  const timestamp = nowSeconds();
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: `t=${timestamp},v1=${"0".repeat(64)}`,
        secret: WEBHOOK_SECRET,
      }),
    WebhookVerificationError,
  );
});

test("verifyStripeSignature rejects a signature computed with another secret", () => {
  const rawBody = succeededEvent("order-1");
  const timestamp = nowSeconds();
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: `t=${timestamp},v1=${signBody(rawBody, "whsec_other", timestamp)}`,
        secret: WEBHOOK_SECRET,
      }),
    WebhookVerificationError,
  );
});

test("verifyStripeSignature rejects a replayed (stale) signature", () => {
  const rawBody = succeededEvent("order-1");
  const staleTimestamp = nowSeconds() - DEFAULT_WEBHOOK_TOLERANCE_SECONDS - 60;
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: signatureHeader(rawBody, staleTimestamp),
        secret: WEBHOOK_SECRET,
      }),
    /outside the tolerance window/,
  );
});

test("verifyStripeSignature rejects a future timestamp outside tolerance", () => {
  const rawBody = succeededEvent("order-1");
  const futureTimestamp = nowSeconds() + DEFAULT_WEBHOOK_TOLERANCE_SECONDS + 60;
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: signatureHeader(rawBody, futureTimestamp),
        secret: WEBHOOK_SECRET,
      }),
    /outside the tolerance window/,
  );
});

test("verifyStripeSignature rejects missing or malformed headers", () => {
  const rawBody = succeededEvent("order-1");
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: undefined,
        secret: WEBHOOK_SECRET,
      }),
    /Missing Stripe-Signature/,
  );
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: `v1=${signBody(rawBody, WEBHOOK_SECRET, nowSeconds())}`,
        secret: WEBHOOK_SECRET,
      }),
    /missing the timestamp/,
  );
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: `t=${nowSeconds()}`,
        secret: WEBHOOK_SECRET,
      }),
    /missing a v1 signature/,
  );
});

test("verifyStripeSignature fails closed without a configured secret", () => {
  const rawBody = succeededEvent("order-1");
  assert.throws(
    () =>
      verifyStripeSignature({
        rawBody,
        signatureHeader: signatureHeader(rawBody),
        secret: "",
      }),
    /webhook secret is not configured/,
  );
});

test("handleWebhook verifies and maps a valid event", async () => {
  const rawBody = succeededEvent("order-42");
  const gateway = new StripeGateway("sk", async () => new Response("{}"), WEBHOOK_SECRET);
  const result = await gateway.handleWebhook(rawBody, {
    "Stripe-Signature": signatureHeader(rawBody),
  });
  assert.deepEqual(result, {
    orderId: "order-42",
    status: "succeeded",
    transactionId: "ch_123",
    payload: {
      id: "pi_123",
      latest_charge: "ch_123",
      status: "succeeded",
      metadata: { orderId: "order-42" },
    },
  });
});

test("handleWebhook matches header names case-insensitively", async () => {
  const rawBody = succeededEvent("order-42");
  const gateway = new StripeGateway("sk", async () => new Response("{}"), WEBHOOK_SECRET);
  const result = await gateway.handleWebhook(rawBody, {
    "stripe-signature": signatureHeader(rawBody),
  });
  assert.equal(result.orderId, "order-42");
});

test("handleWebhook rejects an invalid signature", async () => {
  const rawBody = succeededEvent("order-42");
  const gateway = new StripeGateway("sk", async () => new Response("{}"), WEBHOOK_SECRET);
  await assert.rejects(
    gateway.handleWebhook(rawBody, {
      "Stripe-Signature": `t=${nowSeconds()},v1=${"f".repeat(64)}`,
    }),
    WebhookVerificationError,
  );
});

test("handleWebhook rejects a replayed webhook", async () => {
  const rawBody = succeededEvent("order-42");
  const staleTimestamp = nowSeconds() - DEFAULT_WEBHOOK_TOLERANCE_SECONDS - 60;
  const gateway = new StripeGateway("sk", async () => new Response("{}"), WEBHOOK_SECRET);
  await assert.rejects(
    gateway.handleWebhook(rawBody, {
      "Stripe-Signature": signatureHeader(rawBody, staleTimestamp),
    }),
    /outside the tolerance window/,
  );
});

test("handleWebhook fails closed when no webhook secret is configured", async () => {
  const rawBody = succeededEvent("order-42");
  const gateway = new StripeGateway("sk", async () => new Response("{}"));
  await assert.rejects(
    gateway.handleWebhook(rawBody, {
      "Stripe-Signature": signatureHeader(rawBody),
    }),
    /webhook secret is not configured/,
  );
});

test("handleWebhook maps failed and refunded events", async () => {
  const gateway = new StripeGateway("sk", async () => new Response("{}"), WEBHOOK_SECRET);
  const failedBody = JSON.stringify({
    type: "payment_intent.payment_failed",
    data: { object: { id: "pi_1", metadata: { orderId: "order-1" }, status: "requires_payment_method" } },
  });
  const failed = await gateway.handleWebhook(failedBody, {
    "Stripe-Signature": signatureHeader(failedBody),
  });
  assert.equal(failed.status, "failed");
  const refundedBody = JSON.stringify({
    type: "charge.refunded",
    data: { object: { id: "ch_1", metadata: { orderId: "order-1" }, status: "succeeded" } },
  });
  const refunded = await gateway.handleWebhook(refundedBody, {
    "Stripe-Signature": signatureHeader(refundedBody),
  });
  assert.equal(refunded.status, "refunded");
});

test("handleWebhook rejects unsupported event types", async () => {
  const gateway = new StripeGateway("sk", async () => new Response("{}"), WEBHOOK_SECRET);
  const rawBody = JSON.stringify({ type: "customer.created", data: { object: {} } });
  await assert.rejects(
    gateway.handleWebhook(rawBody, { "Stripe-Signature": signatureHeader(rawBody) }),
    /Unsupported Stripe webhook event type/,
  );
});
