## ADDED Requirements

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
