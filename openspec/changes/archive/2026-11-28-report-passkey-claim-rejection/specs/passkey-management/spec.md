## ADDED Requirements

### Requirement: Recover from a rejected ceremony claim
The service SHALL return HTTP 500 when PostgreSQL rejects marking a login, registration or reauthentication ceremony as consumed.

#### Scenario: Retry an uncommitted claim
- **WHEN** the claim transaction rolls back and the caller retries the valid proof with its original binding before expiry
- **THEN** the proof can succeed once, with no credential, reauthentication or session updates from the rejected attempt
