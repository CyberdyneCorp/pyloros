## Why

Account deletion and account-wide logout can contend for the same sessions and account in opposite orders.

## What Changes

Use a consistent write order for logout and erasure.

## Capabilities

### Modified Capabilities
- grant-sessions

## Impact

PostgreSQL session revocation and access cutoff updates.
