## ADDED Requirements

### Requirement: Resolve relationship check inputs together
After validating the calling service's grant, the check SHALL read the client's model and the subject account's eligibility in one PostgreSQL statement within its decision snapshot.

#### Scenario: Missing model for an inactive account
- **WHEN** the client has no installed model
- **THEN** return HTTP 409 regardless of account eligibility

#### Scenario: Installed model for an inactive account
- **WHEN** an inactive account is checked against an installed model
- **THEN** return HTTP 422 for an unknown permission, and return a denied decision for a known permission
