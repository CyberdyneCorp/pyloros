## ADDED Requirements

### Requirement: Create an operator IAM group

An authorized operator SHALL be able to create a group with a name and optional description on the selected IAM provider.

#### Scenario: PostgreSQL group creation

- **WHEN** an operator creates an ordinary group
- **THEN** return the group with its initial membership and policy attachments, make it visible in the group inventory and record the operator action

#### Scenario: Reserved role namespace

- **WHEN** the submitted group name belongs to the client-role namespace
- **THEN** reject the request without creating a group or a success audit

#### Scenario: Confirm a newly assigned group identifier

- **WHEN** the group contract confirms a creation and the receipt identifies a new directory entry with the submitted name and description at that block
- **THEN** return HTTP 201 with its group UUID and chain identifier after committing the operator audit
- **AND** preserve an omitted or empty description in the creation response

#### Scenario: Confirmed creation cannot be reconciled

- **WHEN** the confirmed receipt cannot identify the new group or PostgreSQL rejects its audit commit
- **THEN** return HTTP 500 without a successful creation audit and retain the confirmed contract state
