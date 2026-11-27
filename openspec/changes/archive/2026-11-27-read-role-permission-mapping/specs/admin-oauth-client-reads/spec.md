## ADDED Requirements

### Requirement: Read the permissions granted by a client role
The service SHALL let an operator read the ordered permission keys assigned to a global role of an active client.

#### Scenario: Role exists without assignments
- **WHEN** an operator requests the mapping for a role present in the current authority
- **THEN** the response identifies the client and role and returns an empty permission list if no grants exist

#### Scenario: Role is absent from the current authority
- **WHEN** a matching permission mapping exists in storage but the role is absent from the selected provider
- **THEN** the request returns a missing-role error
