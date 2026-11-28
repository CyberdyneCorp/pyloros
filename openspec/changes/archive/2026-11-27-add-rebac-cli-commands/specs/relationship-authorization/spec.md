## ADDED Requirements

### Requirement: Typed relationship commands
The operator CLI SHALL expose typed commands to install a model, grant and revoke assignments, and check a permission. Each command SHALL map to its published OpenAPI operation and use the service credential flow.

#### Scenario: Operator revokes an assignment
- **WHEN** the operator previews a revocation
- **THEN** the CLI renders the intended request without contacting the service
- **AND** a confirmed invocation sends the assignment in the DELETE body

#### Scenario: Operator checks access
- **WHEN** the operator checks a permission for a user and object
- **THEN** the CLI reports the backend decision or surfaces the HTTP failure
