## Why

Operators need to update the permissions granted by an application role from the existing role editor.

## What Changes

Accept complete replacements of a role's permission set and record the result in the operator audit log.

## Capabilities

### Modified Capabilities
- `admin-oauth-client-management` gains role permission replacement.

## Impact

Updates PostgreSQL permission assignments for roles in either supported IAM provider.
