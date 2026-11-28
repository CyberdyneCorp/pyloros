## ADDED Requirements

### Requirement: Retry second-factor completion after session rollback
When PostgreSQL rejects the transaction that creates a session, the service SHALL preserve the unused recovery code or authenticator step. Retry SHALL enforce challenge expiry, the authenticator time window and the original binding rules.

#### Scenario: Retry with a password-bound challenge
- **WHEN** the session transaction rolls back and the caller resubmits the same valid password-bound MFA challenge and second factor
- **THEN** the accepting backend issues one session and consumes the factor
- **AND** a subsequent replay of that factor is refused

#### Scenario: Retry with a passkey-bound challenge
- **WHEN** the session transaction rolls back after the backend has claimed the passkey MFA ceremony
- **THEN** retry with the consumed ceremony receives HTTP 401
- **AND** the caller can complete a fresh passkey assertion and present the still-valid second factor to create a session
