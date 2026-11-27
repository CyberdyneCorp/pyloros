## Why
Stripe confirms purchases and subsequent changes asynchronously. Verified events need to update the entitlement ledger even when a provider SDK returns nested objects in a new representation.

## What Changes
Accept signed billing events, apply the corresponding access changes and retain an idempotent processing record.

## Capabilities
### New Capabilities
- stripe-billing-events

## Impact
Adds an inbound HTTP handler and transactional updates to existing PostgreSQL billing tables.
