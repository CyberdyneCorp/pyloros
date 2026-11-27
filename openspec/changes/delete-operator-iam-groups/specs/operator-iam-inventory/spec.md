## ADDED Requirements

### Requirement: Delete an ordinary IAM group

An authorized operator SHALL be able to delete an ordinary group from the selected IAM provider.

#### Scenario: Populated PostgreSQL group

- **WHEN** an operator deletes a group with members and attached policies
- **THEN** remove the group and its links, audit the action and preserve the identities and policies

#### Scenario: Client-role group

- **WHEN** an operator attempts to delete a group reserved for a client role
- **THEN** refuse the mutation and preserve the group

#### Scenario: Failed audit

- **WHEN** a PostgreSQL group deletion cannot be audited
- **THEN** roll back the deletion and preserve access through the group
