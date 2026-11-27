## ADDED Requirements

### Requirement: Read current user roles and permissions
Pyloros SHALL expose GET /api/v1/users/{user_id}/roles and GET /api/v1/users/{user_id}/permissions to administrators and services authenticated with roles:read.

#### Scenario: Scoped service reads current assignments
- **WHEN** a service requests its own client view
- **THEN** the service receives global and eligible organization assignments owned by its exact client ID

#### Scenario: Service selects a different client
- **WHEN** a service requests a client other than its own
- **THEN** the service returns HTTP 403

#### Scenario: Administrator selects a view
- **WHEN** an administrator reads roles without selecting a client
- **THEN** each role includes its client prefix and empty organization roles are omitted

#### Scenario: Administrator requests permissions
- **WHEN** an administrator selects an active client
- **THEN** the response includes its sorted global permissions and organization permission map, including an empty map if appropriate

#### Scenario: Provider cannot resolve membership
- **WHEN** the selected chain provider is unavailable while resolving a linked user
- **THEN** the read reports the service failure
