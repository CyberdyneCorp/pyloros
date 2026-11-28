## Why
A manual test can return after an operator has already selected a replacement component. Operators need to distinguish an in-flight result from a test of the replacement.

## What Changes
Specify the component version used by overlapping v1 manual tests and describe how to verify a replacement or rollback.

## Capabilities
### Modified Capabilities
- `admin-hook-inventory` covers manual execution across committed binding changes.

## Impact
Operator documentation and verification of the existing v1 behavior.
