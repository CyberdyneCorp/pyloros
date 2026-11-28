## Why

Some existing hooks emit a fixed diagnostic message. Operators need an equivalent guest they can build and bind without an interpreter.

## What Changes

Add a Rust guest and a just recipe that embeds the reviewed message when building the WebAssembly artifact.

## Capabilities

### Modified Capabilities
- `wasm-hook-components` includes an event-independent output example.

## Impact

Applies to sample guests and their build and verification recipes.
