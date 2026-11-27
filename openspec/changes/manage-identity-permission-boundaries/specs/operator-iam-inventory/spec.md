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
