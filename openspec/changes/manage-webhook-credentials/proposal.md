## Why

Administrators need to replace a webhook signing credential and retire destinations that should no longer receive events.

## What Changes

Add secret rotation and subscription removal to the webhook administration API.

## Capabilities

### Modified Capabilities
- `webhook-history` gains audited credential rotation and removal.

## Impact

Use the existing PostgreSQL subscription and delivery tables and the deployment master key.
