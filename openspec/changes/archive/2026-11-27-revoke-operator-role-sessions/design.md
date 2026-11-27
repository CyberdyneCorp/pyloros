## Decisions

Keep the PostgreSQL session record so a repeated request can resolve the identifier. Commit its status change and the operator audit together. Resolve session identifiers within the configured provider.

## Verification

Exercise active, expired, missing and previously revoked sessions. Compare audit failure, overlapping requests, the unchanged browser and CLI, and the resulting role inventory and effective access.
