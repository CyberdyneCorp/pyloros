## Why

The token service needs a transactional way to validate and claim an authorization code for an authenticated client.

## What Changes

Add S256 verification, expiry, redirect, resource and active-account checks. Reuse of a claimed code revokes its associated session and refresh tokens.

## Capabilities

### Modified Capabilities

- `authorization-code-storage` gains checked redemption and replay handling.

## Impact

This application operation precedes token issuance and is internal to the service.
