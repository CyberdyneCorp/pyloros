## Why

OAuth clients can hold resource-bound refresh grants across a writer switch. Operators need to distinguish successful rotation from a completed administrator revocation.

## What Changes

Extend the session handoff contract and guide to cover the OAuth token endpoint.

## Capabilities

### Modified Capabilities

- `grant-sessions` covers committed refresh grants and administrative revocation across writer changes.

## Impact

Applies to mixed-backend deployment verification.
