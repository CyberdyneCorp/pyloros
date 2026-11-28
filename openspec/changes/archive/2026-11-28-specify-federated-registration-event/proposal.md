## Why
A registration subscriber needs to distinguish account creation from the first time a provider identity links to an existing account.

## What Changes
Specify which successful external OAuth callbacks emit a registration webhook.

## Capabilities
### Modified Capabilities
- `external-oauth` defines registration events across callback handoff and replay.

## Impact
The existing callback and webhook behavior gains a documented contract.
