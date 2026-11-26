## Why
Existing clients need to exchange authorization codes over HTTP during migration.

## What Changes
Serve the authorization-code grant when discovery and signing credentials are configured.

## Impact
The token endpoint, issuer configuration and PostgreSQL resource registry.
