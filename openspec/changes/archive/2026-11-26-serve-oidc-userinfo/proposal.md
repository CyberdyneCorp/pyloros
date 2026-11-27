## Why

Relying parties need to resolve a user access token to the current account after a successful token exchange.

## What Changes

Serve the UserInfo operation advertised in issuer discovery. Return current subject and available identity claims and apply the configured revocation policy.

## Capabilities

### Modified Capabilities
- `oauth-token` gains the UserInfo operation.

## Impact

Reads account and revocation data from PostgreSQL.
