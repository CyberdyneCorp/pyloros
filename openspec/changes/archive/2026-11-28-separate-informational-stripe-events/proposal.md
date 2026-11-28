## Why
An informational invoice currently waits behind a purchase that holds the same subscription or payment reference. Its ledger acknowledgement can complete independently because it never modifies an entitlement.

## What Changes
Scope billing-reference locks to grants and revocations. Preserve event-ID deduplication for every signed event and the established handled result for partial refunds.

## Capabilities
### Modified Capabilities
- `stripe-billing-events` covers concurrent delivery of distinct events for one reference.

## Impact
Stripe notification processing on PostgreSQL.
