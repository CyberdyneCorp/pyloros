## Why

A hook that reads one field can fail before execution when an unrelated JSON number exceeds the host floating-point range.

## What Changes

Accept such numbers throughout component event admission.

## Capabilities

### Modified Capabilities
- wasm-hook-components

## Impact

Component dry runs, offline fixtures and the isolated worker.
