## ADDED Requirements

### Requirement: Administer user sessions

The service SHALL authorize administrative session inventory and individual revocation through the existing REST API.

#### Scenario: Browse session activity

- **WHEN** an administrator lists sessions
- **THEN** return the requested page in descending creation order, the filtered total and owner and activity metadata.
- **WHEN** the request omits the activity filter
- **THEN** include only unexpired sessions that have not been revoked.

#### Scenario: End an individual session

- **WHEN** an administrator revokes an existing session
- **THEN** disable refresh for the session, record the operator and affected session, and return an empty success response.

#### Scenario: Refuse an unauthorized operator

- **WHEN** an unauthenticated or unauthorized caller submits a request
- **THEN** deny access before exposing session data or changing state.

#### Scenario: Revoke the same session again

- **WHEN** an operator repeats a successful revocation
- **THEN** record the new session revocation time, preserve previous refresh-token revocation times and audit the action again.

#### Scenario: Roll back failed revocation

- **WHEN** either the authentication event or operator audit record cannot be written
- **THEN** preserve the prior session and token state and return an error.
