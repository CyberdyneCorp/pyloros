## Why

Operators need the same account and session metrics in the dashboard and CLI during migration.

## What Changes

Serve the four administrative analytics reads from PostgreSQL.

## Capabilities

### New Capabilities
- `admin-analytics` defines overview totals, authentication methods, registrations and session activity.

## Impact

Adds read-only endpoints under /api/v1/admin/analytics.
