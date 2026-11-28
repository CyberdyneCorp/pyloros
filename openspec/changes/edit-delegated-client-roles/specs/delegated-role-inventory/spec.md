## ADDED Requirements

### Requirement: Manage the calling client's roles
A service client authenticated for delegated role discovery SHALL be able to create and delete roles in its own catalog. The service SHALL identify the calling client in the audit trail.

#### Scenario: Create a global role
- **WHEN** the caller posts a valid new role key and optional description to its role catalog
- **THEN** return HTTP 201 and the created role with zero members

#### Scenario: Delete a role
- **WHEN** the caller deletes its role
- **THEN** retire its global and organization assignments, remove its permission mappings and return HTTP 204

#### Scenario: Isolate role names
- **WHEN** two clients use the same role key
- **THEN** deleting one client's role preserves the other client's assignments and mappings

#### Scenario: Confirm client-role catalog changes on chain

- **WHEN** an operator or delegated client creates a role in the chain-backed catalog
- **THEN** verify the newly assigned group against the confirmed block before committing the role audit and clearing any previous permission mapping
- **WHEN** a caller retires the role
- **THEN** confirm removal of each organization-scoped group before removing the global group and committing the deletion audit
- **AND** if a later transaction fails, roll back the local mapping and audit changes while retaining earlier confirmed chain effects
