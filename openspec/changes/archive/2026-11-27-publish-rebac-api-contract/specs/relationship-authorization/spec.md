## ADDED Requirements

### Requirement: Machine-readable relationship API contract
The project SHALL publish an OpenAPI description of the model, assignment and permission-check operations, their service scopes and their response semantics.

#### Scenario: Client follows a grant and revoke example
- **WHEN** a service installs the example model, grants a user membership and links a child collection to the parent
- **THEN** the example permission check allows the user on the child
- **AND** withdrawing the membership makes the next check deny access
