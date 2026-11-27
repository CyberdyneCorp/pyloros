## ADDED Requirements

### Requirement: Stage immutable hook components
The service SHALL allow current administrators to install validated component bytes and retrieve them by their SHA-256 digest.

#### Scenario: Install or retry a component
- **WHEN** authorized uploads contain the same compatible bytes
- **THEN** atomically persist one artifact and one operator audit entry, return its identity to every caller, and leave active hooks unchanged

#### Scenario: Retrieve staged bytes
- **WHEN** an administrator requests an existing artifact by digest
- **THEN** return its exact bytes as application/wasm

#### Scenario: Reject an invalid component
- **WHEN** installation fails the component validation checks
- **THEN** return the validation failure and persist no artifact
