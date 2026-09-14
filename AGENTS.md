# AGENTS.md — drop-payment-stripe

Stripe payment gateway plugin for Drop indie commerce (#21).

## Toolchain

- Node >= 22, npm 10+
- `npm ci`, `npm run build`, `npm test`, `npm run typecheck`

## Contract

Built on [`@droposs/plugin-sdk`](https://www.npmjs.com/package/@droposs/plugin-sdk)
(plugin API v2, `^0.4.0` from the npm registry).

## Security invariants

- `createPaymentIntent` must send `application/x-www-form-urlencoded`, never
  JSON (Stripe's API rejects or misparses JSON bodies).
- `handleWebhook` verifies `Stripe-Signature` before parsing: HMAC-SHA256 over
  `${timestamp}.${rawBody}`, constant-time compare, 300 s replay window, and
  fails closed when `STRIPE_WEBHOOK_SECRET` is absent.
- Uses only `node:crypto`; no new dependencies.
- The host must supply the raw webhook body for signatures to validate.
