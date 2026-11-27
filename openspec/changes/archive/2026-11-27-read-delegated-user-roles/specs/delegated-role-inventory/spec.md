## ADDED Requirements

### Requirement: Read a user's roles for a service client
An active service client with a valid bearer granting `roles:manage` SHALL be able to retrieve a user's current roles for that client.

#### Scenario: Read global and organization roles
- **WHEN** the caller requests `GET /api/v1/clients/me/users/{user_id}/roles` for an existing user
- **THEN** return the user identifier and the client's sorted global role keys, plus organization roles for active memberships when present

#### Scenario: No eligible assignments
- **WHEN** the user has no eligible assignments for the calling client
- **THEN** return an empty roles array and omit the organization roles field

#### Scenario: Unknown user
- **WHEN** the authenticated client requests an unknown user identifier
- **THEN** return HTTP 404
