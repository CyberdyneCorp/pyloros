## Why

Operators need to grant and revoke inherited access for an individual user while preserving the policies shared by the rest of the group.

## What Changes

Support adding and removing ordinary group memberships through the configured IAM provider. Keep client-role assignment on its dedicated endpoints.

## Capabilities

### Modified Capabilities

- `operator-iam-inventory` gains group membership management.

## Impact

Operator HTTP routes, IAM identity lookup, effective permissions, group inventory and audit.
