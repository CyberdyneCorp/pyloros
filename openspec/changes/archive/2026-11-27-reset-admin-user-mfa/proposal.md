## Why

Administrators need to recover accounts whose users have lost access to their authenticator.

## What Changes

Add an audited administrative reset for TOTP and recovery codes.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` supports operator-initiated MFA recovery.

## Impact

The existing admin console and CLI can reset a user's enrolled authenticator.
