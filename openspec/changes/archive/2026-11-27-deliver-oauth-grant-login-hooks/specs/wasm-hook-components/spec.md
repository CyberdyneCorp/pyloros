## ADDED Requirements

### Requirement: Deliver OAuth user grant login events
When login dispatch is enabled, the service SHALL deliver one login event per selected recipient for each committed authorization-code or approved device-code session, using the token request origin and the interactive login privacy rules.

#### Scenario: Grant remains retryable
- **WHEN** dispatch cannot select all active recipients or the transaction fails
- **THEN** roll back the session, grant consumption and deliveries

#### Scenario: Unsupported ID token signing
- **WHEN** a user grant commits a session under HS256 and cannot issue the requested ID token
- **THEN** consume the grant without binding a session ID to the code, retain the success audit and login deliveries and return the signing error

#### Scenario: No new user session
- **WHEN** a client refreshes tokens, polls a pending device code or replays a consumed code
- **THEN** enqueue no login event
