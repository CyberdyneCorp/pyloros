## Why

Account holders need the existing frontend to show and manage previously registered passkeys after switching backend.

## What Changes

List active passkey metadata, rename a credential and revoke it with recent authentication and last-sign-in-method protection.

## Capabilities

### New Capabilities
- `passkey-management` covers credential inventory for a signed-in user.

## Impact

Uses existing PostgreSQL session and passkey data and browser session credentials.
