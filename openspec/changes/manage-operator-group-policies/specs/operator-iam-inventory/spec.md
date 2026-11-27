## ADDED Requirements

### Requirement: Manage the policies attached to a group

An authorized operator SHALL be able to attach and detach an existing IAM policy on a group.

#### Scenario: Group member inherits a grant

- **WHEN** an operator attaches an applicable allow policy to a group
- **THEN** the group inventory includes the attachment once and access evaluation considers the policy for group members

#### Scenario: Remove the only grant

- **WHEN** an operator detaches the only policy granting a member access
- **THEN** the next access check denies that access and the policy and membership still exist

#### Scenario: PostgreSQL audit failure

- **WHEN** recording an attachment or detachment fails
- **THEN** the transaction preserves the previously committed relationships
