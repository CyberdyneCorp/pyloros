## Context

User credentials, IAM identity links and organization memberships can live in PostgreSQL even when the selected IAM provider owns group membership.

## Decisions

Separate group retrieval from role projection. Project global groups directly and restrict organization groups to current active memberships. Use the same projection when creating credentials and reading profiles. Capture a consistent provider configuration for each lookup. Bound remote calls and distinguish an unavailable provider from an authoritative empty result.

## Rollout

Keep chain-backed traffic on its current service until provider selection, successful reads and outage behavior have been compared across the affected operations.
