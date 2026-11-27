## Why

A component may be built from a definition that changes before the component is selected. Operators need to identify the reviewed source when migrating a hook.

## What Changes

Allow a binding request to supply the SHA-256 of the source used to build its component. Include a buildable Rust example targeting the shared hook interface.

## Capabilities

### Modified Capabilities

- wasm-hook-components

## Impact

The optional field applies to the v2 selection endpoint. Existing callers can continue selecting components by artifact digest alone.
