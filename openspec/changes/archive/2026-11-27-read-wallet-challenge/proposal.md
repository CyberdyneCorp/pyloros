## Why

A wallet client needs to check whether an issued sign-in challenge is still pending.

## What Changes

Implement the public challenge status read on the shared account database.

## Capabilities

### New Capabilities

- `wallet-authentication` defines the public challenge status operation.

## Impact

Wallet sign-in HTTP routing and PostgreSQL challenge status.
