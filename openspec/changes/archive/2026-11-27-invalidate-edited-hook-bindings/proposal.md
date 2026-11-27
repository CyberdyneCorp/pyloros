## Why
An operator can edit hook source through another writer after selecting a component. Future events must reflect the new source or wait for a replacement binding.

## What Changes
Invalidate the selection in the PostgreSQL source-edit transaction.

## Capabilities
### Modified Capabilities
- wasm-hook-components

## Impact
Shared database migration, hook authoring and rollout.
