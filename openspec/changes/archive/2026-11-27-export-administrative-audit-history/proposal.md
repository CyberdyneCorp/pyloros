## Why

Operators need to download audit records and verify their chain independently of the running service.

## What Changes

Add a chronological NDJSON download with optional time bounds.

## Capabilities

### Modified Capabilities
- `admin-audit` gains a streaming export.

## Impact

Reads the existing PostgreSQL audit log and supports the current browser and command-line download flows.
