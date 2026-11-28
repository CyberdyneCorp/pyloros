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

#### Scenario: Add overlaps an uncommitted removal
- **WHEN** the adding statement can still see the committed membership while another writer is removing it
- **THEN** treat it as already present, record the operator action, and allow the pending removal to complete

#### Scenario: Concurrent additions encounter the unique constraint
- **WHEN** two writers both see an absent membership and attempt to insert it
- **THEN** the committed addition retains the membership, and a writer rejected by the unique constraint returns HTTP 500 without recording a success audit

#### Scenario: Chain-backed membership
- **WHEN** the group contract confirms the requested mutation and the database commits its operator audit
- **THEN** acknowledge the membership change
- **WHEN** the transaction reverts or confirmation remains uncertain
- **THEN** return an error and omit the success audit
