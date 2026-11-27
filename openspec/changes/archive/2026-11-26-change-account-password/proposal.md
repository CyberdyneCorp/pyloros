## Why

Account owners need to replace their password from the existing Preferences screen and invalidate credentials issued before the change.

## What Changes

Implement first-party password change with credential verification, replacement password validation, session revocation and a recorded outcome.

## Capabilities

### Modified Capabilities

- `account-passwords` gains authenticated password replacement.

## Impact

Existing clients use the same request and response. Both backends can use the replacement hash in the shared PostgreSQL database.
