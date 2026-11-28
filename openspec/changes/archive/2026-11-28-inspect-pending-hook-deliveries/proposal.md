## Why
Deleting a hook removes its queued deliveries. An event-wide pending count includes work for other hooks and cannot identify when the selected hook has drained.

## What Changes
Allow the existing queue inspection command and just recipe to select a hook by UUID.

## Capabilities
- Modified capability: wasm-hook-components
