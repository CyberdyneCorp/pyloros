## ADDED Requirements

### Requirement: Database-backed password login decision
The credential step SHALL return the same invalid-credentials decision for unknown accounts, absent passwords and mismatches while recording distinct audit reasons. It SHALL refuse inactive accounts after verifying the password. It SHALL check the current credential and enrollment before advancing a successful attempt.

#### Scenario: Enrolled account
- **WHEN** a valid password belongs to an active TOTP-enrolled account
- **THEN** the service records a successful MFA challenge and returns a short-lived challenge without creating a session

#### Scenario: Additional login policy
- **WHEN** a valid password belongs to an active account without TOTP
- **THEN** the caller can continue the login transaction to evaluate further authentication requirements
