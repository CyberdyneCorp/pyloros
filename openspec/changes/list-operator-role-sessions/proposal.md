## Why

Operators inspecting a role need to see which identities hold active sessions and when those sessions expire.

## What Changes

Expose a role's current sessions through the operator API.

## Capabilities

### New Capabilities

- `operator-role-sessions` covers the provider-selected session listing for a role.

## Impact

The roles panel and CLI gain access to the session inventory on the Rust service.
