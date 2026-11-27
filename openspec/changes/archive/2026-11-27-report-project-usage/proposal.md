## Why

Administrators need to see which accounts use a project and which projects an account can access.

## What Changes

Expose a project overview, a project's users and a user's projects through the administrative REST API.

## Capabilities

### New Capabilities
- `project-usage` reports project access and completed sign-ins.

## Impact

The service reads existing PostgreSQL client, account, entitlement and authorization code records.
