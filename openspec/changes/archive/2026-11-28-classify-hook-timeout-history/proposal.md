## Why

Operators use v1 execution history to distinguish timeouts from other hook failures. A guest can report a timeout itself.

## What Changes

Classify automatic delivery errors using the v1 timeout convention.

## Capabilities

### Modified Capabilities
- wasm-hook-components

## Impact

Execution history written by the component worker.
