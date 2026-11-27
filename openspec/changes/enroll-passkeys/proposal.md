## Why

People switching to the Rust backend need to enroll a new passkey from their existing clients and use it after either service handles the next request.

## What Changes

Add the start and finish operations for passkey enrollment. Preserve existing credential records, client bindings and in-flight enrollment across a backend switch.

## Capabilities

### Modified Capabilities

- `passkey-management` gains enrollment for accounts with recent authentication.

## Impact

The Rust HTTP service reads and writes enrollment state in PostgreSQL. Verification requires a WebAuthn implementation that supports the credential formats offered to clients.
