## Context

User credentials, IAM identity links and organization memberships can live in PostgreSQL even when the selected IAM provider owns group membership.

## Decisions

Separate group retrieval from role projection. Project global groups directly and restrict organization groups to current active memberships. Use the same projection when creating credentials and reading profiles. Capture a consistent provider configuration for each lookup. Bound remote calls and distinguish an unavailable provider from an authoritative empty result.

Configuration lives in the running process. Validate and derive signer material before taking the update lock. Serialize each change with its audit append. A storage failure returns an error after the runtime configuration has changed, so an operator should read back the current settings before retrying.

## Rollout

Keep chain-backed traffic on its current service until provider selection, successful reads and outage behavior have been compared across the affected operations.
