## ADDED Requirements

### Requirement: Preserve graph ownership across client lifecycle changes
The service SHALL use the active client registration and its UUID to authorize relationship checks. Deactivating a registration SHALL preserve its model and assignments. Physical deletion of that registration SHALL remove its graph.

#### Scenario: Pause and reactivate a service registration
- **WHEN** the administrator deactivates a client with direct and inherited access
- **THEN** checks starting after commit on any replica return HTTP 401 for that client's token
- **AND** reactivating the same registration restores its graph for an otherwise eligible token

#### Scenario: Replace a physically deleted registration
- **WHEN** a new registration uses the same client identifier with a new UUID
- **THEN** its authorized check returns HTTP 409 until its own model is installed
- **AND** the former registration's token cannot check the replacement graph
- **AND** other clients retain their models and assignments
