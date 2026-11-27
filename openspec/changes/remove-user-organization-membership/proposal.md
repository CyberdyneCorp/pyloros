## Why

Operators need to revoke access that depends on a user's membership in an organization.

## What Changes

Implement explicit membership removal with primary organization clearing and scoped role revocation.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` gains organization membership removal.

## Impact

The Rust endpoint coordinates membership records, IAM role assignments, role events and operator auditing.
