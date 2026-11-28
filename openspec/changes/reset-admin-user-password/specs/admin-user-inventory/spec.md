## ADDED Requirements

### Requirement: Replace a user's password as an administrator

The service SHALL let an authorized operator assign a policy-compliant password to an existing account and revoke its outstanding sessions.

#### Scenario: Recover an account

- **WHEN** an operator submits a valid replacement password
- **THEN** return the target user identifier and reset confirmation, store the replacement hash, set the account token cutoff and revoke the user's previously unrevoked sessions.

#### Scenario: Record a reset

- **WHEN** the reset commits
- **THEN** record the operator action and account activity with the number of newly revoked sessions, including zero on a subsequent reset.

#### Scenario: Audit storage fails

- **WHEN** an audit write fails
- **THEN** roll back the password, token cutoff and session changes.

#### Scenario: Overlapping resets

- **WHEN** two operators successfully replace the same user's password while sessions are active
- **THEN** the last committed reset supplies the current password, each successful reset records its audit events, and each session contributes to one revocation count.

#### Scenario: Recover a legacy bcrypt account through an Argon2 writer

- **WHEN** an operator resets a bcrypt-backed account through a replica configured for Argon2
- **THEN** store an Argon2id version 19 hash for the replacement password and record one successful reset. An Argon2 peer accepts the replacement password.
- **AND** with token revocation enforced, both backends reject the prior access token, refresh token and password.
