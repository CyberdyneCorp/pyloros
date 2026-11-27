## Why
Operator account creation needs consistent request validation across clients and deployments.

## What Changes
Use the credential document decoder for the operator account creation route and preserve its authorization order.

## Capabilities
### Modified Capabilities
- admin-user-inventory

## Impact
The operator account creation endpoint and its HTTP tests.
