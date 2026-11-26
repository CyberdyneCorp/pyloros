## Why

After code exchange, the issuer needs a session and refresh credential that both services can recognize.

## What Changes

Create a session and refresh record in the code claim transaction and issue an RS256 refresh JWT for the configured issuer.

## Capabilities

### New Capabilities

- `grant-sessions` covers session persistence and refresh credential issuance for OAuth user grants.

## Impact

This increment is internal to the exchange service. It reuses existing PostgreSQL tables.
