## Why
Operators need to check a ported hook before installing it. A versioned component contract lets guest code and the Rust host evolve independently.
## What Changes
Publish the first hook WIT world and an administrator endpoint that validates an uploaded component and identifies its exact bytes by SHA-256.
## Capabilities
### New Capabilities
- wasm-hook-components
## Impact
Adds a v2 administrative operation and a Rust binary-format dependency.
