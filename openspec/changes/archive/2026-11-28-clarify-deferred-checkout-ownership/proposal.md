## Why
A deferred checkout can commit its customer mapping before its product becomes available. Reconciliation needs to distinguish that state from a checkout which supplied no product key.

## What Changes
Clarify the ownership and grant requirements for missing product metadata, unavailable catalog entries and repaired products.

## Capabilities
### Modified Capabilities
- stripe-billing-events

## Impact
The Stripe event contract and operator instructions for deferred checkouts.
