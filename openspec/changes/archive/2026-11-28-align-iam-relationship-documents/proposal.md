## Why
A discrepancy in numeric document decoding can cause a relationship change to commit when the reference refuses the request.

## What Changes
Use the shared IAM decoder for group policy attachment, user group membership, direct user policy attachment and identity boundary assignment.

## Capabilities
### Modified Capabilities
- `operator-iam-inventory` defines request handling for these relationship writes.

## Impact
Four operator POST routes, their validation and regression coverage.
