## Why

Operators need to provision identities that can participate in IAM independently or on behalf of a user.

## What Changes

Add operator identity creation to the configured IAM provider.

## Capabilities

### Modified Capabilities
- `operator-iam-inventory` gains identity creation.

## Impact

Operator HTTP requests, database persistence, contract calls and audit history.
