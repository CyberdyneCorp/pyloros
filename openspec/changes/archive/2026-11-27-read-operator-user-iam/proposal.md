## Why

The user administration page needs to display a user's identity, policies, memberships and identity token information before and after an operator changes access.

## What Changes

Provide the two read operations that populate the user IAM panel from PostgreSQL and the configured chain provider.

## Capabilities

### Modified Capabilities

- `operator-iam-inventory` gains user assignment and identity token views.

## Impact

User detail HTTP handlers, policy and group projections, role sessions and chain reads.
