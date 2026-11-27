## Why
User grant exchanges establish sessions and must notify login hook recipients.

## What Changes
Queue login hooks for authorization-code and approved device grants. Preserve committed session effects on unsupported ID-token signing.

## Capabilities
### Modified Capabilities
- wasm-hook-components
- device-authorization

## Impact
OAuth token endpoint and the existing login component worker.
