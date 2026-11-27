## ADDED Requirements

### Requirement: Create an operator IAM group

An authorized operator SHALL be able to create a group with a name and optional description on the selected IAM provider.

#### Scenario: PostgreSQL group creation

- **WHEN** an operator creates an ordinary group
- **THEN** return the group with its initial membership and policy attachments, make it visible in the group inventory and record the operator action

#### Scenario: Reserved role namespace

- **WHEN** the submitted group name belongs to the client-role namespace
- **THEN** reject the request without creating a group or a success audit
