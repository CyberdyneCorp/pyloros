## Why

During migration an account can request recovery from each backend before either message arrives. Clients need to know which link remains usable after a password change.

## What Changes

Document the lifetime of distinct outstanding reset credentials across sequential redemptions.

## Capabilities

### Modified Capabilities
- `account-passwords` covers recovery links delivered for the same account.

## Impact

Clarifies the existing password recovery behavior across backend handoff.
