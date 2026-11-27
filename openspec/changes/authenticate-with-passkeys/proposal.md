## Why

Users with a discoverable credential need to sign in through the existing client after the API moves to Rust.

## What Changes

Provide sign-in options and assertion verification. Preserve one-time challenges and subsequent session or MFA state across a backend switch.

## Capabilities

### New Capabilities

- `passkey-login` covers sign-in using a registered discoverable credential.

## Impact

Uses the configured relying party, client origins, PostgreSQL challenge and credential records, first-party sessions and MFA.
