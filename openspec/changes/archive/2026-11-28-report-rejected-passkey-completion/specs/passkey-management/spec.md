## ADDED Requirements

### Requirement: Recover from discarded passkey verification results
After a successful ceremony claim, the service SHALL return HTTP 500 when PostgreSQL explicitly rejects the transaction that stores an enrollment or reauthentication result.

#### Scenario: Rejected enrollment
- **WHEN** a valid enrollment proof consumes its ceremony and the credential transaction rolls back
- **THEN** the credential and enrollment activity are absent, the claimed ceremony remains consumed, and the caller can enroll with a fresh challenge

#### Scenario: Rejected reauthentication
- **WHEN** the transaction saving verified reauthentication rolls back after the ceremony claim
- **THEN** the previously committed credential counter, last-use time and session proof remain intact, and reauthentication requires a fresh ceremony
