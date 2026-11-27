## Why
Existing operators validate hook source before saving it. A Rust migration needs the same authoring feedback.

## What Changes
Parse source and apply authoring restrictions in an isolated Rust worker, then expose the compatible administrator validation operation.

## Capabilities
### Modified Capabilities
- admin-hook-inventory

## Impact
Hook worker, administrator API and migration tests.
