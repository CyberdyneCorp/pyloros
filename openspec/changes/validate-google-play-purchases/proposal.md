## Why
Android applications need to claim a verified subscription and immediately read the resulting entitlement.

## What Changes
Add authenticated Google Play subscription validation backed by the Android Publisher API.

## Capabilities
### New Capabilities
- google-play-purchases

## Impact
Reads Google Play subscription state and writes purchase ownership and entitlements to PostgreSQL.
