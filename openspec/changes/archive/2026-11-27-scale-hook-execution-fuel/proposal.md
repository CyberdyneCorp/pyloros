## Why

Two accepted event contexts exhausted the worker's fixed fuel allowance while a compiled Rust hook was decoding its input. Reading the same event type from a shorter context succeeded.

## What Changes

Scale the instruction allowance with the byte length of an admitted event. Keep a fixed upper bound and retain the service timeout.

## Capabilities

### Modified Capabilities

- wasm-hook-components

## Impact

Applies to staged, manual and automatically dispatched component execution.
