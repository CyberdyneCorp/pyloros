## Why
Group and policy writes can commit inputs that the reference rejects during parsing, including advancing a policy version.

## What Changes
Apply the shared IAM document decoder to group creation and policy creation and replacement.

## Capabilities
### Modified Capabilities
- `operator-iam-groups` specifies group creation input.
- `operator-iam-inventory` specifies policy definition input.

## Impact
Three operator writes, regression tests and input validation.
