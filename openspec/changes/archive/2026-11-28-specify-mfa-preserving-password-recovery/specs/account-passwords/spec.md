## ADDED Requirements

### Requirement: Preserve MFA enrollment during operator password recovery
An operator password reset that migrates a bcrypt credential to Argon2 SHALL preserve the account's authenticator enrollment, last accepted authenticator step and recovery-code usage.

#### Scenario: Recover an enrolled account with partially used recovery codes
- **WHEN** an operator replaces the password on an Argon2-configured writer
- **THEN** used recovery codes remain spent and unused recovery codes remain available
- **AND** the previous session's refresh credential is refused

#### Scenario: Sign in after the reset
- **WHEN** the user submits the replacement password after the revocation cutoff on a compatible peer
- **THEN** the peer requires the enrolled second factor
- **AND** the other backend can complete that challenge with the existing authenticator and issue a session usable by the peer
