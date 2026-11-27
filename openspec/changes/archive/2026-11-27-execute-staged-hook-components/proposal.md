## Why
Operators need to exercise a staged hook with synthetic input before activating it.
## What Changes
Introduce an isolated Rust component worker and an administrator dry-run endpoint for staged components.
## Capabilities
### Modified Capabilities
- `wasm-hook-components` gains bounded execution of a staged component.
## Impact
Package the worker alongside the API. Operators can dry-run hooks during migration.
