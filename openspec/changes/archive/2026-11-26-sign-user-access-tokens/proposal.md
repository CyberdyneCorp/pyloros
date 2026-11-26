## Why

Resource servers need a verifiable access token that carries the user's effective grants.

## What Changes

Sign access tokens from verified user grants, loading account, organization and entitlement state from PostgreSQL.

## Capabilities

### Modified Capabilities

- `grant-sessions` gains user access-token issuance.

## Impact

Internal token exchange gains an access-token signing operation.
