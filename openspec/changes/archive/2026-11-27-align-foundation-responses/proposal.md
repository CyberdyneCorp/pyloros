## Why

Monitoring tools and discovery clients receive inconsistent method responses during migration. Operators also need to distinguish an unreadable migration table from multiple recorded revisions.

## What Changes

Align method rejection for both probes and all three issuer discovery routes. Include the failure category in readiness responses for missing migration objects and multiple revisions.

## Impact

This changes HTTP method errors and schema diagnostics visible to clients.
