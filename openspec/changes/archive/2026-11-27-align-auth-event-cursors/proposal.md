## Why
Some hand-built continuation cursors select different responses and create different audit records across implementations.

## What Changes
Accept the supported hexadecimal identifier formats inside history cursors and reject week dates that fall outside the supported calendar.

## Capabilities
### Modified Capabilities
- `admin-audit` defines cursor handling for both authentication history directories.

## Impact
The change affects the global and per-user authentication event listings.
