## ADDED Requirements

### Requirement: Grant and withdraw a client-owned relationship
PUT and DELETE /api/v1/clients/me/rebac/relationships SHALL require the client’s current relationship management grant. Both operations SHALL return 204 on success, including an identical retry.

#### Scenario: Assign an account or related object
- **WHEN** an application creates a relationship
- **THEN** require a destination type allowed by the current model and an existing account for a user destination

#### Scenario: Withdraw a relationship
- **WHEN** an application removes an edge
- **THEN** remove only that exact edge in its own graph

#### Scenario: Audit failure or repeat delivery
- **WHEN** a write changes the graph
- **THEN** commit the change and its client audit together and omit additional audit records for no-op retries
