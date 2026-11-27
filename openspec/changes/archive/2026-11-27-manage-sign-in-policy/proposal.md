## Why

Operators need to manage email confirmation for password sign-in while both backends share the deployment.

## What Changes

Expose administrative reads and updates for the persisted sign-in policy.

## Capabilities

### New Capabilities

- `sign-in-policy` — Configure the email confirmation interval and retain an operator audit trail.

## Impact

The routes use the existing administrator credentials, PostgreSQL policy and audit chain. Password sign-in reads the committed setting.
