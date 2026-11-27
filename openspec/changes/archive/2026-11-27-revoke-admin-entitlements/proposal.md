## Why

Operators need to withdraw a user's or organization's product access while retaining its grant history.

## What Changes

Implement the administrative entitlement deletion route and record its actor and target.

## Capabilities

### Modified Capabilities
- `admin-entitlements` gains revocation.

## Impact

Updates existing PostgreSQL grants and the administrative audit chain. Post-commit hook execution is a migration gate.
