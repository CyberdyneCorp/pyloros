## Why

An external provider must be able to return a user to Pyloros after authorization started on either backend.

## What Changes

Handle Google and Microsoft callbacks, match the external identity to the appropriate local account, and finish the selected browser or CLI flow.

## Capabilities

### Modified Capabilities

- `external-oauth` gains callback processing.

## Impact

Integrates the provider clients, shared state, user identities, managed wallets, sessions, CLI exchange codes and authentication audit events.
