## Why
Clients inspecting validation errors receive different issue types for very long integer strings in queries and JSON fields.

## What Changes
Align the distinction between integer-size, parsing and field-bound errors for wide decimal strings.

## Capabilities
### Modified Capabilities
- `http-responses` specifies wide integer text diagnostics.

## Impact
The shared integer text parser, including pagination limits and hook timeout fields.
