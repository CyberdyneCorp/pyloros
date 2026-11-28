## Why
A rollout operator may need evidence from each expected webhook replica. Repeated samples can all reach a single healthy instance.

## What Changes
Add an optional coverage check to the existing unsigned webhook route probe.

## Impact
Affects the operator CLI and the stripe-billing-events specification.
