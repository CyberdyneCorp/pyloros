## Why

During migration, clients need to revoke a token through either backend and have both services enforce that decision.

## What Changes

Implement client-authenticated revocation at POST /api/v1/auth/oauth2/revoke. Preserve the existing form contract, cache policy, quota behavior and audit records.

## Impact

The two services share PostgreSQL session, refresh-token and token revocation records. No schema change is expected.
