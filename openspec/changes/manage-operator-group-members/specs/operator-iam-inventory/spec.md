## ADDED Requirements

### Requirement: Manage ordinary group memberships

An operator SHALL be able to add and remove an identified user from an ordinary IAM group.

#### Scenario: Membership grants and revokes inherited access

- **WHEN** an operator adds a user to a group with a policy that grants access
- **THEN** the group includes that identity once and its applicable grants participate in the next decision
- **WHEN** the membership is removed
- **THEN** subsequent decisions exclude grants from that membership and the shared policy remains attached

#### Scenario: Role-managed group

- **WHEN** an operator requests a membership change on a client-role group through the ordinary group interface
- **THEN** refuse the request and preserve the role assignment

#### Scenario: Failed PostgreSQL audit

- **WHEN** recording the operator action fails
- **THEN** roll back the membership change
