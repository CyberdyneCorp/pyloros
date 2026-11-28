## Why
A replacement account can have the same email as an erased subscriber. Operators need to know whether a late subscription update can give the replacement account access.

## What Changes
Specify what happens to Stripe customer mappings, processed events and subsequent renewals when an account is erased or deletion rolls back.

## Capabilities
### Modified Capabilities
- stripe-billing-events

## Impact
Documents verified behavior on shared PostgreSQL during a writer handoff.
