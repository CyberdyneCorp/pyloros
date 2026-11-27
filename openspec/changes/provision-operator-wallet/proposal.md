## Why

An administrator needs to provision a wallet for an account created without one.

## What Changes

Add the administrator wallet provisioning operation and preserve existing account addresses across sequential requests.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` adds wallet provisioning for existing accounts.

## Impact

The administrator API, PostgreSQL account key storage and administrator audit log.
