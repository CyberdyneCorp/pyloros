## Why
Operators need to stage verified component bytes before assigning versions to hooks.
## What Changes
Add administrator upload and download by content digest, backed by PostgreSQL.
## Capabilities
### Modified Capabilities
- `wasm-hook-components` gains immutable artifact storage.
## Impact
Deploy an additive PostgreSQL table before enabling the new endpoints.
