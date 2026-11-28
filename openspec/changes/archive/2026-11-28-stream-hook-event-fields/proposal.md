## Why
The example guests build a sorted index of the whole event to read one field. Wide objects with ascending keys exhaust the worker budget even when they fit the event size limit.

## What Changes
Read only the requested event field while consuming the entire JSON document. Preserve the final value when a decoded key occurs more than once.

## Capabilities
### Modified Capabilities
- `wasm-hook-components` covers the event-name and numeric counter guests.

## Impact
Rebuild the example components to use the new field reader. Existing digest-bound components retain their original code.
