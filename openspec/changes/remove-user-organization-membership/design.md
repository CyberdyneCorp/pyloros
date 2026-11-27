## Decisions

Validate the operator, user and organization. Accept a departure from an inactive organization. Clear a matching primary assignment and resolve organization-bound roles using the configured IAM provider. Record revoked roles in the audit and honor the configured event delivery behavior.

## Verification

Exercise both IAM providers, state after retries, orphaned role assignments, failures during revocation or auditing, both deployment orders, and the existing CLI and console.
