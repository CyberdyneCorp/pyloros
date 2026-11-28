## Why

Subscription payloads can carry renewal dates at the subscription or item level. An ambiguous choice can give the customer the wrong access window.

## What Changes

Specify field precedence for subscription fulfillment and exercise it in the billing adapter tests.

## Capabilities

### Modified Capabilities

- `stripe-billing-events` defines how subscription item metadata and expiry are selected.

## Impact

Applies to Stripe subscription fulfillment and its regression coverage.
