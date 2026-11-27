## Why

Services need to check their current registration and token lifetime after switching issuers.

## What Changes

Add the existing GET /api/v1/clients/me route using service bearer authentication.

## Impact

The route reads client registration and revocation state from PostgreSQL.
