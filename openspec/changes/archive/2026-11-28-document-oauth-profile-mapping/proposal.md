## Why
Federated sign-in uses different email and display fields for each upstream provider. The handling of missing and empty fields should be explicit.

## What Changes
Document the mapping of optional provider strings and cover email fallback in tests.

## Capabilities
### Modified Capabilities
- `external-oauth` specifies provider profile mapping.

## Impact
Provider exchange tests and the callback contract.
