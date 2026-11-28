## Why
A mixed-case UUID URN prefix can resolve a resource on one backend while producing a field validation error on the other.

## What Changes
Apply the existing REST field error format to mixed-case UUID URN prefixes in shared typed UUID fields.

## Capabilities
### Modified Capabilities
- `http-responses` specifies UUID URN prefix validation.

## Impact
Typed UUID path, query and body fields that use the shared validator observe the same prefix rule.
