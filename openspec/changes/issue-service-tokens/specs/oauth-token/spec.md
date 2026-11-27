## ADDED Requirements

### Requirement: Issue OAuth service access tokens

The token endpoint SHALL support the client_credentials grant for registered services using the shared signing configuration and PostgreSQL records.

#### Scenario: Successful service authentication

- **WHEN** an eligible client authenticates and requests permitted scopes and an allowed audience
- **THEN** return a bearer access token with the registered lifetime, verified client identity and granted scopes. Record successful use before returning it.

#### Scenario: Default scopes

- **WHEN** an authenticated client omits scope
- **THEN** grant the registered scope set and report it in the same form as the existing endpoint.

#### Scenario: Refuse disallowed requests

- **WHEN** authentication fails, the client is disabled, the grant is unavailable, a scope or audience is disallowed, or the per-client quota is exhausted
- **THEN** return the applicable OAuth error and record the issuance decision according to the existing contract.

#### Scenario: Revoke across implementations

- **WHEN** either implementation issues a service token
- **THEN** the other implementation can revoke it for the registered client and the reference introspection endpoint reports it inactive with enforcement enabled.
