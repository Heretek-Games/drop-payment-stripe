# Stripe

Stripe payment gateway plugin for Drop indie commerce (#21).

## Build

```sh
npm ci
npm run build
npm test
npm run typecheck
```

## Configuration

| Environment variable | Purpose |
| :--- | :--- |
| `STRIPE_SECRET_KEY` | Stripe API secret key used for `POST /v1/payment_intents` |
| `STRIPE_WEBHOOK_SECRET` | Endpoint signing secret (`whsec_...`) used to verify webhooks |

Without `STRIPE_WEBHOOK_SECRET` the gateway still registers, but every
`handleWebhook` call is rejected: verification fails closed rather than
accepting unsigned events.

## API behaviour

- `createPaymentIntent` sends `application/x-www-form-urlencoded` data (Stripe's
  required encoding) with `amount`, `currency`, `metadata[orderId]`,
  `receipt_email`, and flattened `metadata[...]` entries. `client_secret`,
  `next_action.redirect_to_url.url`, and the intent status are mapped to the
  SDK result.
- `handleWebhook` verifies the `Stripe-Signature` header per Stripe's scheme:
  HMAC-SHA256 over `${timestamp}.${rawBody}` with the endpoint secret, compared
  in constant time, rejecting timestamps outside a 300 second tolerance window.
  Only then is the event parsed and mapped (`payment_intent.succeeded`,
  `payment_intent.payment_failed`, `payment_intent.canceled`, `charge.failed`,
  `charge.refunded`).

## Host requirements

Signature verification only works on the exact bytes Stripe signed. The host
must pass the **raw request body** (string or bytes) to `handleWebhook`, not a
re-serialized JSON object. Header names are matched case-insensitively.
