## Why
Two signed checkouts can supply different account IDs for one previously unmapped Stripe customer. Operators need to know which account receives access and how to interpret the other event.

## What Changes
Specify customer ownership and redelivery outcomes for competing checkouts, including a rejected commit.

## Capabilities
### Modified Capabilities
- stripe-billing-events

## Impact
Stripe webhook compatibility checks and billing reconciliation guidance.
