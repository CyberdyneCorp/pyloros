## ADDED Requirements

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
