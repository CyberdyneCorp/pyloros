# admin-user-inventory Specification

## Purpose
Define the administrator-facing account directory, identity summaries and session activity projection.

## Requirements

### Requirement: Inspect accounts as an administrator

The service SHALL permit authorized operators to list users and inspect an individual account using the existing API.

#### Scenario: Search the directory

- **WHEN** an administrator filters the user directory
- **THEN** return the filtered total and a newest-first page, including identity counts and administrator status.
- **WHEN** search text contains wildcard characters
- **THEN** match the text literally in the email or wallet address.

#### Scenario: Inspect an account

- **WHEN** an administrator requests an existing user
- **THEN** return account metadata, linked identity summaries, bootstrap administrator status and the latest session activity.
- **WHEN** the user identifier is unknown
- **THEN** return the established not-found response.

#### Scenario: Protect user information

- **WHEN** the caller lacks administrative access
- **THEN** deny the request before disclosing account data or query validation details.

### Requirement: Inspect a user's active passkeys

The service SHALL allow administrators to read the active passkeys for a specified user across relying parties, independently of the sign-in feature setting.

#### Scenario: Render the inventory

- **WHEN** an authorized operator requests credentials for an existing user
- **THEN** return their active credentials oldest first with the identifier, label, relying party, timestamps and backup flags, and mark the response no-store.

#### Scenario: Distinguish an empty account from a missing one

- **WHEN** the user exists with no active passkeys
- **THEN** return an empty list.
- **WHEN** the user does not exist
- **THEN** return the user-not-found error.

### Requirement: Revoke a user's passkey as an operator

The service SHALL allow an administrator to revoke an active credential belonging to the specified user, including the last credential or one for a different relying party, regardless of the passkey sign-in setting.

#### Scenario: Remove a lost device

- **WHEN** the operator revokes an active credential
- **THEN** return HTTP 204, preserve existing sessions, and commit the credential change with account activity and operator audit records.

#### Scenario: Retry the request

- **WHEN** the credential already appears revoked or belongs to another account
- **THEN** return the missing-credential response.
- **WHEN** two requests independently observe the credential as active before either update commits
- **THEN** both may succeed and each success records its operator action.

#### Scenario: Credential metadata changes concurrently

- **WHEN** an operator observes an active credential and a pending rename or sign-in metadata update commits before the revocation write
- **THEN** the revoked credential retains the metadata the operator observed and the operator audit identifies that credential by its observed label.

### Requirement: Reset a user's authenticator enrollment

The service SHALL let authorized administrators clear a user's TOTP secret and recovery codes for lockout recovery.

#### Scenario: Reset an enrolled authenticator

- **WHEN** an operator resets an existing user's MFA
- **THEN** return HTTP 204, remove the user's TOTP enrollment and recovery codes, and record the operator and prior enrollment state in the audit trails.

#### Scenario: Repeat a reset

- **WHEN** the user already has MFA disabled
- **THEN** clear any pending enrollment secret and recovery codes, return HTTP 204, and audit the reset with the prior disabled state.

#### Scenario: Roll back an incomplete reset

- **WHEN** either audit write fails
- **THEN** roll back the account and recovery-code changes together.

#### Scenario: Continue after account recovery

- **WHEN** the reset commits with a password login challenge outstanding
- **THEN** the former TOTP cannot finish that challenge, existing sessions remain valid, and a fresh password login can proceed without the removed factor.
