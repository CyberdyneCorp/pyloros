## ADDED Requirements

### Requirement: Author hook definitions
The service SHALL accept authorized creation and editing of hook definitions, validate submitted source without executing it, and record each successful operation in the audit history.

#### Scenario: Create a definition
- **WHEN** an operator supplies an available name, supported event and acceptable source
- **THEN** return the persisted definition with its identifier and execution settings

#### Scenario: Partially edit a definition
- **WHEN** an operator updates selected settings on an existing hook
- **THEN** apply supplied non-null fields and preserve the other settings

#### Scenario: Reject invalid input
- **WHEN** an input violates the field schema, the source policy or name uniqueness
- **THEN** return the applicable validation or conflict response and preserve the stored definition

#### Scenario: Audit failure
- **WHEN** recording the operator action fails
- **THEN** roll back the mutation and preserve the previous component selection

#### Scenario: Concurrent creation with the same name
- **WHEN** two requests both observe that a name is available and attempt to insert it
- **THEN** commit one definition and audit entry, and return an internal error for the failed insertion
