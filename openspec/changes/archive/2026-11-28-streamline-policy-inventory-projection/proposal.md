## Why
The policy directory builds an intermediate PostgreSQL JSONB document for every statement, then converts it to text for the service to read. Large inventories pay the conversion cost on each request.

## What Changes
Aggregate statement rows directly into ordered JSON for directory reads, export and import refresh.

## Capabilities
### Modified Capabilities
- operator-iam-inventory

## Impact
Affects reads from PostgreSQL. Existing stored statement columns and indexes are sufficient.
