## ADDED Requirements

### Requirement: Manage an identity permission boundary

An authorized operator SHALL be able to set, replace and clear the policy that bounds an IAM identity's permissions.

#### Scenario: Apply or replace a boundary

- **WHEN** a new boundary is committed
- **THEN** the user detail returns that boundary and subsequent checks apply it to the identity's existing grants

#### Scenario: Clear a boundary

- **WHEN** an operator clears a boundary
- **THEN** remove its restriction while preserving the identity and independently assigned grants

#### Scenario: Failed PostgreSQL audit

- **WHEN** a boundary change cannot be audited
- **THEN** the previously committed boundary continues to govern access

#### Scenario: Switch boundary writers with a policy deletion in flight

- **WHEN** ingress holds boundary changes and policy deletions during a PostgreSQL writer switch
- **THEN** policy lookup and permission evaluation remain available while previously admitted writes finish
- **AND** after reopening writes, setting a boundary to the deleted policy returns HTTP 404 without a success audit if deletion committed
- **AND** if deletion rolled back, setting the surviving policy succeeds and the next permission check applies the boundary

### Requirement: Look up a boundary subject

An authorized operator SHALL be able to retrieve a single IAM identity from the selected provider by its identity identifier.

#### Scenario: Identity exists

- **WHEN** an operator selects an existing identity
- **THEN** return its identity details, including the associated user when present
