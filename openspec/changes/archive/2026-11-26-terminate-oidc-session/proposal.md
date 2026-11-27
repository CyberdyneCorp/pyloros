## Why

Relying parties need to end an issuer session across backend transitions.

## What Changes

Accept browser logout through query or form parameters, clear issuer credentials and validate the client's requested return address.

## Capabilities

### Modified Capabilities
- `oauth-token` gains RP-initiated logout.

## Impact

Updates session, refresh, access revocation and audit records in PostgreSQL.
