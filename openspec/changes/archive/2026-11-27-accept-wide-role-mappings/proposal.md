## Why
A role mapping with a small permission set can exceed the framework's default request size when the JSON document is padded or uses a wide encoding.

## What Changes
Apply the existing role-mapping decoder to large documents on operator and delegated PUT routes.

## Capabilities
### Modified Capabilities
- admin-oauth-client-management

## Impact
Two REST routes share the replacement handler. The catalog mutation and authorization rules apply to both.
