## Why
Permission and role creation can reject valid encoded requests or silently save an omitted description when a client submits an out-of-range number.

## What Changes
Use the IAM request decoder for catalog creation, including wide documents and scalar validation errors.

## Capabilities
### Modified Capabilities
- admin-oauth-client-management

## Impact
Operator and delegated POST routes for client permissions and roles.
