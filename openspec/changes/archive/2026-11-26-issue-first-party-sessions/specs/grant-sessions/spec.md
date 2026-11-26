## ADDED Requirements

### Requirement: First-party session issuance
After authentication, the service SHALL issue access and refresh credentials for the same active user and session. The access credential SHALL contain the current account authorization and authentication context and omit OAuth client, scope, audience and permission claims. The session and its refresh record SHALL participate in the caller transaction.

#### Scenario: Continue a session on another deployment
- **WHEN** a first-party session commits and the other deployment uses the same issuer, keys and database
- **THEN** it can authenticate the access credential and rotate the refresh credential with the original authentication context
