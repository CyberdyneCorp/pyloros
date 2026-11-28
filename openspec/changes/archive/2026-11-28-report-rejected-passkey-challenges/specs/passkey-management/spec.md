## ADDED Requirements

### Requirement: Issue options only for committed passkey ceremonies
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a login, registration or reauthentication ceremony at commit.

#### Scenario: Challenge storage rolls back
- **WHEN** a browser or native client requests options and the ceremony transaction is rejected at commit
- **THEN** return the error without a ceremony identifier, public-key options, binding cookie or native binding secret

#### Scenario: Issue options after recovery
- **WHEN** the client retries after the database accepts writes
- **THEN** return the challenge and binding for the newly committed ceremony
