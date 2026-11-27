## Why

An account owner who has lost a password needs to recover the account through the existing emailed link and reset form.

## What Changes

Accept reset requests, deliver a single-use credential to the registered address and redeem it to replace the password. Preserve interoperability during a rolling migration.

## Capabilities

### Modified Capabilities

- `account-passwords` supports recovery by email.

## Impact

Both services share the password-reset token store, account credentials, organization memberships and session state in PostgreSQL.
