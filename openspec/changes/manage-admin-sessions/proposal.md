## Why

Operators need to inspect sessions and end an individual session during a mixed-backend rollout.

## What Changes

Add the existing administrative session collection and revocation routes to the Rust service.

## Capabilities

### New Capabilities

- `admin-sessions` — List sessions with owner and activity metadata and revoke a selected session.

## Impact

Uses the existing PostgreSQL sessions, refresh tokens and audit records. The existing administrator clients continue using their current routes.
