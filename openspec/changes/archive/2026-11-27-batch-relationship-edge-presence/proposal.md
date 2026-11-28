## Why

Checking a wide graph can issue separate PostgreSQL requests for each inherited rule on objects with no outgoing object relationships.

## What Changes

Read a bounded set of outgoing edges across queued objects in the existing transaction. Reuse complete results for small branches and request individual relations on larger branches.

## Impact

Relationship permission checks retain the same decisions, limits and primary-database snapshot. The service requires no additional migrations.
