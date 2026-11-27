## Why

A deployment can use a different authority for IAM group membership than the database that stores sessions. Reading stale group membership when issuing credentials can grant access after a role has been removed.

## What Changes

Resolve group membership through the active IAM backend. Apply the same role naming and tenant membership rules to each backend's results. Preserve the observable difference between an empty assignment and a failed lookup.

## Capabilities

### New Capabilities

- `iam-role-claims` defines authoritative membership reads for user role claims.

## Impact

Affects first-party sessions, delegated tokens, introspection and user profile responses.
