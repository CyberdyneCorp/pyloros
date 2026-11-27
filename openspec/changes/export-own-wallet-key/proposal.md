## Why

Deployments that permit custodial wallet export need a way for the authenticated account holder to retrieve their stored key.

## What Changes

Add an opt-in self-service read with a per-account quota and first-party session authentication.

## Capabilities

### Modified Capabilities
- `wallet-authentication` adds account-bound key export.

## Impact

Affects the user profile API and deployment configuration.
