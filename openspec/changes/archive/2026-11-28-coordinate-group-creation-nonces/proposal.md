## Why
Group and policy preparations can use the same chain signer across replicas. Group creation currently bypasses the coordination used for operator policy mutations.

## What Changes
Coordinate operator group creation through the existing PostgreSQL signer lock while preparing the unsigned call.

## Capabilities
### Modified Capabilities
- `operator-iam-groups` specifies cross-replica coordination for unsigned group creation.

## Impact
Operator group creation when chain IAM is active.
