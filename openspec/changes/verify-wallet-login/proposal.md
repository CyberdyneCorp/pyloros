## Why

Wallet clients need to exchange a signed challenge for a session during a backend handoff.

## What Changes

Add the public verification operation and its account, audit and session effects.

## Capabilities

### Modified Capabilities

- `wallet-authentication` covers sign-in with a stored challenge.

## Impact

Public authentication, Ethereum signature recovery and shared PostgreSQL state.
