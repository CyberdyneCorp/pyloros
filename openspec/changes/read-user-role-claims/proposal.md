## Why

Applications need a current view of user access between token issuances.

## What Changes

Expose user role and permission reads to administrators and service clients with roles:read.

## Capabilities

### Modified Capabilities
- `iam-role-claims` exposes fresh assignments and permission mappings.

## Impact

Adds two read operations to the users API.
