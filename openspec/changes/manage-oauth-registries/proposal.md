## Why

Operators need to inspect and maintain the scopes, protected resources and browser origins used by OAuth clients during the backend migration.

## What Changes

Implement the existing administrative collection and detail APIs for all three registries, including creation, partial changes and deactivation. Preserve the source of each entry, access control and the metadata consumed by the admin console and CLI.

## Impact

Changes affect issuer discovery, client registration, resource grants and browser-origin policy. Persist administrator-managed records and their audit events in PostgreSQL.
