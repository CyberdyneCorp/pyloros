## Why
An operator reviewing a hook port needs the configured timeout, network permission and privacy setting alongside its source and component digests.

## What Changes
Include those settings for active and inactive hooks in the existing inventory command.

## Capabilities
### Modified Capabilities
- `admin-hook-inventory` reports the stored execution settings.

## Impact
The change adds fields to CLI JSON. The command continues to use its read-only transaction and existing exit codes.
