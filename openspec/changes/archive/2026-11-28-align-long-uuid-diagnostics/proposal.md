## Why
Malformed UUIDs longer than a valid URN currently produce a generic byte length in some REST validation responses. Clients comparing field errors need the same character and group diagnostics across backend changes.

## What Changes
Preserve validation details for malformed UUID text regardless of its length.

## Capabilities
### Modified Capabilities
- `http-responses` covers the diagnostic returned for malformed typed UUIDs.

## Impact
Shared UUID validation for REST request fields.
