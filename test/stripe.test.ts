import test from "node:test";
import assert from "node:assert/strict";
import { MockPluginContext } from "@droposs/plugin-sdk";
import Plugin from "../src/index.js";

test("drop-payment-stripe registers a payment gateway", async () => {
  const ctx = new MockPluginContext("drop-payment-stripe", ["commerce:payment", "network"]);
  await new Plugin().init(ctx);
  assert.equal(ctx.paymentGateways.size, 1);
  assert.equal(ctx.paymentGateways.get("stripe")?.name, "Stripe");
});
