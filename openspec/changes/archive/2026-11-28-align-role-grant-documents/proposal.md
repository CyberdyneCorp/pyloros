## Why
Operator and service role grants currently parse numeric input differently from other IAM writes. The difference can change whether an assignment is created.

## What Changes
Use the IAM document decoder and shared validation error rendering for both grant endpoints.

## Capabilities
### Modified Capabilities
- `delegated-role-inventory` specifies grant document behavior for operator and service callers.

## Impact
Role assignment input handling and regression tests.
