## Why

Account recovery requires operators to replace a lost password and end sessions established under the previous credential.

## What Changes

Support operator password resets for existing accounts, including accounts without a current password.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` gains an audited password reset operation.

## Impact

The existing operator console and CLI can reset credentials through the shared database.
