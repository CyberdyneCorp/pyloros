## Why
Store billing transitions need to deliver events to selected component versions and expose their execution history to operators.
## What Changes
Queue grant and revocation events in the billing transaction and execute committed deliveries in the bounded hook worker.
## Capabilities
### Modified Capabilities
- `wasm-hook-components` gains post-commit delivery of store entitlement events.
## Impact
Apply a queue migration and enable dispatch on the Rust deployment owning billing mutations.
