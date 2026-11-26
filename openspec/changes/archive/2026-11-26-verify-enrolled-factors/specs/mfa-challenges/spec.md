## ADDED Requirements

### Requirement: Verify an enrolled login factor
The factor verifier SHALL accept existing encrypted enrollments for active users and consume the factor in the caller’s PostgreSQL transaction.

#### Scenario: Authenticator code
- **WHEN** a six-digit code matches the current thirty-second step or an adjacent step
- **THEN** accept it only if the matched step strictly advances the account’s last used step.

#### Scenario: Recovery code
- **WHEN** a submitted code matches an unused recovery record for that account
- **THEN** consume it once and report recovery authentication to the session issuer.

#### Scenario: Rollback
- **WHEN** session creation rolls back after accepting the factor
- **THEN** the factor remains available to a subsequent transaction.
