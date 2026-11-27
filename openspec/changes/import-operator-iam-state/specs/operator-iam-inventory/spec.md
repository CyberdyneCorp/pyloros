## ADDED Requirements

### Requirement: Import the configured chain IAM snapshot

An authorized operator SHALL be able to reconcile the IAM state exposed by the configured chain provider with PostgreSQL and receive a report of imported entities and gaps.

#### Scenario: Refresh an existing policy

- **WHEN** the snapshot contains a known policy and its provider cannot enumerate statements
- **THEN** retain its local identifier and rules, refresh its catalog attributes and report that its statement bodies were skipped

#### Scenario: Apply group attachments

- **WHEN** an imported group references an imported policy
- **THEN** associate the group and policy using their local identifiers

#### Scenario: Aborted import

- **WHEN** the database cannot apply the import or record its operator audit
- **THEN** roll back the import and return an error
