## ADDED Requirements

### Requirement: Read user organization memberships

An operator SHALL be able to list a user's explicit memberships in active organizations. The result SHALL order organizations by case-insensitive short name with unnamed entries last and include their directory fields, timestamps and string-valued metadata.

#### Scenario: Account has only a primary organization

- **WHEN** the user has no explicit memberships
- **THEN** return an empty organization list

#### Scenario: Unknown account

- **WHEN** an authorized operator requests the memberships of an unknown user identifier
- **THEN** return a missing-user error identifying that account

#### Scenario: Read existing directory metadata

- **WHEN** a stored organization contains a historical map or list of key-value pairs
- **THEN** expose its entries as strings, including nested values and full-width integers
