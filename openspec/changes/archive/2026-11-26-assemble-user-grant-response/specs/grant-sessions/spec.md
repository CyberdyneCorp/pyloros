## ADDED Requirements

### Requirement: Assemble a user grant response
The issuer SHALL create the session and assemble a bearer response in the caller's transaction. Both signers SHALL use one authorization snapshot resolved for the access token's effective audience. The response SHALL report the access-token lifetime in seconds and the sorted granted scopes.

#### Scenario: Scoped credentials
- **WHEN** the grant includes openid and offline_access
- **THEN** the response includes an ID token and refresh token alongside the access token

#### Scenario: Access only
- **WHEN** the grant includes neither openid nor offline_access
- **THEN** the response omits both optional credentials
