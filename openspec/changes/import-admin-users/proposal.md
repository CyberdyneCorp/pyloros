## Why

Operators use CSV uploads to provision multiple password accounts and inspect a result for each row.

## What Changes

Implement the administrative bulk user endpoint using the shared PostgreSQL schema.

## Capabilities

### New Capabilities

- `admin-user-import` — Import verified accounts from a multipart CSV file.

## Impact

The existing CLI and console can submit their current files. Account creation, registration integrations and audit records share the import transaction.
