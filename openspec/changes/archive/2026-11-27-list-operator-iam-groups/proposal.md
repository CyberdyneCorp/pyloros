## Why

Operators and the user administration console need to see the groups exposed by the selected IAM provider.

## What Changes

Add the group inventory to the operator REST API.

## Capabilities

### New Capabilities

- `operator-iam-groups` exposes the provider's group inventory.

## Impact

The Rust service reads group records, membership counts and policy references. The existing CLI and dashboard consume the response.
