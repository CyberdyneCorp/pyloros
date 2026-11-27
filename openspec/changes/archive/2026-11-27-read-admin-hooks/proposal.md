## Why
Operators need to inspect installed hooks and historical runs throughout the runtime migration.
## What Changes
Serve authenticated administrative reads for configuration, stored source and execution history.
## Capabilities
### New Capabilities
- admin-hook-inventory
## Impact
Adds three read-only routes over the existing PostgreSQL hook tables.
