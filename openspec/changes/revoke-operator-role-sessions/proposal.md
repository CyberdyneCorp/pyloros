## Why

Operators need to terminate a temporary grant and trace the change to the acting administrator.

## What Changes

Allow operators to revoke a selected role session in the configured IAM provider.

## Capabilities

### Modified Capabilities

- `operator-role-sessions` gains revocation, audit and subsequent access checks.

## Impact

The existing roles panel and CLI can end an active role session.
