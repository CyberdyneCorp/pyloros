## Why
Signed checkouts can carry a historical account UUID spelling. A parser mismatch can defer a valid purchase or associate a customer using a spelling that should be refused.

## What Changes
Decode the signed subject with the existing legacy UUID rules before resolving customer ownership.

## Capabilities
### Modified Capabilities
- stripe-billing-events

## Impact
Affects signed Stripe grant events with an explicit account reference.
