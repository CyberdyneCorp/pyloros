## ADDED Requirements

### Requirement: Manage administrator status

The service SHALL allow authorized operators to grant or revoke administrator access for eligible accounts.

#### Scenario: Change administrator access

- **WHEN** the operator sets a user's administrator status
- **THEN** return the new status and record both the action and previous status. A demotion from a stored administrator role advances the user's token cutoff.

#### Scenario: Protect administrative accounts

- **WHEN** the operator attempts to change their own status or a configuration-managed administrator
- **THEN** refuse the change and record a refusal activity with the reason.

#### Scenario: Audit failure during a change

- **WHEN** a successful status change cannot be audited
- **THEN** roll back the role and token cutoff together.

#### Scenario: Concurrent changes

- **WHEN** overlapping requests each observe a user's previous administrator status
- **THEN** audit each accepted request with the status it observed.

#### Scenario: Invalid role input

- **WHEN** the administrator flag has an invalid type or value
- **THEN** report the invalid field and preserve its submitted JSON value, including integer digits beyond the native machine range.
