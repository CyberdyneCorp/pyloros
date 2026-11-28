## ADDED Requirements

### Requirement: Report live token state to authenticated service callers

Pyloros SHALL accept a token at POST /api/v1/auth/introspect and authenticate the resource server with a service bearer credential.

#### Scenario: Inactive token

- **WHEN** the submitted token is invalid, expired, revoked or bound to a disabled account or client
- **THEN** return an inactive result with no identity fields.

#### Scenario: Active service token

- **WHEN** the submitted credential belongs to an active registered service
- **THEN** report the client identity, scope, audience when present and validity times according to the existing REST contract.

#### Scenario: Active user token

- **WHEN** the submitted credential identifies an eligible user
- **THEN** report the verified token context and current identity, entitlements, organizations, roles and audience-scoped permissions as applicable to that account.

#### Scenario: Unauthenticated resource server

- **WHEN** the caller supplies no acceptable service credential
- **THEN** reject the request without disclosing the submitted token's state.

#### Scenario: IAM authority changes during a session

- **WHEN** the service introspects a user token after the running process changes IAM authority
- **THEN** resolve the current role projection using the selected authority, including after a switch back to PostgreSQL.
