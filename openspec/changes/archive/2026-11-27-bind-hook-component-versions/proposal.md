## Why
A hook needs a stable component version for delivery while its existing event, privacy settings and source remain available during migration.
## What Changes
Allow administrators to select, inspect and release a staged artifact for an existing hook.
## Capabilities
### Modified Capabilities
- `wasm-hook-components` gains audited version bindings.
## Impact
Apply a PostgreSQL migration after the artifact table.
