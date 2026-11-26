## ADDED Requirements

### Requirement: Audit successful authorization code grants
A successful authorization code exchange SHALL record a verifiable token grant event in the session transaction. The event SHALL identify the account, client, session, granted scopes and available request attribution.

#### Scenario: Committed grant
- **WHEN** the session transaction commits
- **THEN** its audit record can be verified from the stored fields

#### Scenario: Rolled back grant
- **WHEN** the session transaction rolls back
- **THEN** its success event is discarded
