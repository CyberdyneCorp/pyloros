## Why
An operator can replace a selected component without leaving a hook unbound. Checking coverage alone cannot confirm that the deployment still uses the reviewed components.

## What Changes
Add a developer command to compare a newly generated inventory report with a local reviewed report before producer handoff.

## Capabilities
### Modified Capabilities
- `admin-hook-inventory` gains reviewed-report verification.

## Impact
Cutover tooling and operator documentation.
