## Why
The role mapping endpoints treat numeric input differently from other IAM catalog writes. A request containing an oversized integer in an ignored field can clear an existing role mapping.

## What Changes
Use the shared IAM decoder and validation error serializer for operator and delegated permission replacements.

## Capabilities
### Modified Capabilities
- admin-oauth-client-management

## Impact
Affects both role mapping PUT routes and their validation responses.
