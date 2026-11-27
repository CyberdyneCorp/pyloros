## Why

Operators need to grant an identity temporary access through the policies attached to a role.

## What Changes

Create a time-limited role session and expose it to access evaluation and the session inventory.

## Capabilities

### Modified Capabilities

- `operator-role-sessions` supports assuming a role for a specified duration.

## Impact

Operator role management, PostgreSQL session storage, audit and effective IAM decisions.
