## Why
Role assignments can change while an operator edits webhook subscriptions. Consumers need to know which changes affect outstanding deliveries.

## What Changes
Specify how grants and revocations select recipients and how repeated grants affect delivery history.

## Capabilities
### Modified Capabilities
- `iam-role-claims` covers webhook selection during role changes.

## Impact
PostgreSQL regression coverage for the existing role event publisher.
