## Decisions

Validate the operator, user and organization. Accept a departure from an inactive organization. Clear a matching primary assignment and resolve organization-bound roles using the configured IAM provider. Record revoked roles in the audit and honor the configured event delivery behavior.

## Verification

Exercise both IAM providers, state after retries, orphaned role assignments, failures during revocation or auditing, both deployment orders, and the existing CLI and console.

## Current verification

Both PostgreSQL writers revoke the target organization's roles, clear its primary assignment and preserve global roles and other memberships. Each selected hook runs once for each revoked role. A retry on the peer records an empty revocation list. A partial binding rolls back the removal. Chain-backed role revocation depends on confirmed chain writes tracked in `submit-chain-iam-transactions`.
