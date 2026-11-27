## Why

A signed-in user needs to confirm their presence before managing credentials from the existing frontend.

## What Changes

Support starting and completing passkey reauthentication against the current first-party session.

## Capabilities

### Modified Capabilities

- `passkey-login` gains an authenticated challenge for refreshing proof of presence.

## Impact

Uses the existing credential, challenge, MFA and recent-authentication records in PostgreSQL.
