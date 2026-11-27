## Why
Canary replicas need to enqueue component events while a designated process executes them. A draining worker also needs to run after producer traffic returns to the previous service.

## What Changes
Add an independent worker selection setting and preserve automatic startup by default.

## Capabilities
### Modified Capabilities
- wasm-hook-components

## Impact
Background component delivery and rollout configuration.
