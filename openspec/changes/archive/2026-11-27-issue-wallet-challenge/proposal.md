## Why

Wallet sign-in clients need a fresh challenge they can sign and later verify.

## What Changes

Serve the challenge issuance endpoint using the shared challenge table.

## Capabilities

### Modified Capabilities

- `wallet-authentication` adds challenge creation.

## Impact

Public sign-in routing, source quotas and PostgreSQL challenge persistence.
