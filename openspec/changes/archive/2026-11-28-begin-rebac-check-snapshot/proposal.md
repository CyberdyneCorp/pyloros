## Why
Every permission check currently spends a separate database round trip setting transaction isolation after beginning the transaction.

## What Changes
Open the read-only repeatable-read transaction with its settings in the initial statement.

## Capabilities
### Modified Capabilities
- `relationship-authorization` specifies transaction setup for permission checks.

## Impact
The PostgreSQL read path for relationship authorization.
