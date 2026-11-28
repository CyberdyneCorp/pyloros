## Why

Erasing a long authentication history issues one update round trip per event.

## What Changes

Persist each bounded set of rewritten events together.

## Impact

The administrator erasure endpoint retains its existing receipt, hashing and transaction semantics.
