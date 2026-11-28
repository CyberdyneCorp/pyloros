## Why

Large deferred billing inventories require a complete cutover record even when the operator runs the report with limited memory.

## What Changes

Read the ledger in batches and stage the JSON until the read transaction succeeds.

## Impact

Changes the implementation of the read-only deferred-event report.
