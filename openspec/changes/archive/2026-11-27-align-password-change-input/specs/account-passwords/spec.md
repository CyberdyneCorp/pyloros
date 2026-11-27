## ADDED Requirements

### Requirement: Decode password change requests before validating credentials
The password change handler SHALL decode Unicode JSON documents before authenticating the caller and validate the current and new password fields after checking the session. Unknown properties SHALL be ignored in otherwise valid requests, including documents larger than two MiB.

#### Scenario: Unauthenticated caller with valid JSON
- **WHEN** a caller without a session submits a syntactically valid document with invalid field types
- **THEN** return the authentication challenge

#### Scenario: Wide encoded password change
- **WHEN** an authenticated caller supplies both valid password fields in UTF-16 or UTF-32 JSON
- **THEN** change the credential and apply the existing session revocation policy
