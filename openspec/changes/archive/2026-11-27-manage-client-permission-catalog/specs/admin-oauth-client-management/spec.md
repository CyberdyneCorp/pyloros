## ADDED Requirements

### Requirement: Maintain the client permission catalog
Administrators SHALL be able to add uniquely named permissions for active clients and remove an existing permission together with every role assignment to that key in the same client.

#### Scenario: Register a permission
- **WHEN** an operator submits a valid new key and the catalog has capacity
- **THEN** persist its optional description, record the operator action and return the created permission

#### Scenario: Retire an assigned key
- **WHEN** an operator removes a key used by several roles
- **THEN** the catalog and all affected role mappings reflect the removal on the next read

#### Scenario: Audit fails
- **WHEN** the audit write fails during a catalog change
- **THEN** roll back the catalog and mapping changes
