## Why

Operators need to explain an access decision for an identity using the policies, memberships, role sessions and boundary currently in effect.

## What Changes

Expose the read-only IAM evaluation operation through the configured provider.

## Capabilities

### New Capabilities

- `operator-iam-evaluation` reports a decision and the statements that contributed to it.

## Impact

Operator HTTP routing, policy matching, active role sessions and provider reads.
