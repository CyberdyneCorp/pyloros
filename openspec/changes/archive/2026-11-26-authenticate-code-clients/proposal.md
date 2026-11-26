## Why

A code exchange must establish the calling application and its registered grant before evaluating the user's code.

## What Changes

Read active OAuth clients from PostgreSQL and check their type, credentials, rotation window and grant registration at the exchange entry point.

## Capabilities

### Modified Capabilities

- `authorization-code-storage` adds client authentication to checked redemption.

## Impact

Token-exchange callers supply the presented client ID and optional secret. Public clients still require PKCE during redemption.
