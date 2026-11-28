## Why
Operator and service-client role edits can prepare calls for the same chain signer on different API replicas. Both currently bypass the signer's PostgreSQL lock.

## What Changes
Use the common signer lock for membership edits and the group creation needed by a scoped grant.

## Capabilities
### Modified Capabilities
- `iam-role-claims` covers concurrent unsigned role preparations.

## Impact
The chain-backed branches of operator and delegated user role grant and revocation.
