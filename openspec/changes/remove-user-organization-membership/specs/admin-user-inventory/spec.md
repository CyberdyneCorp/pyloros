## ADDED Requirements

### Requirement: Remove organization membership

An operator SHALL be able to remove a user's membership in an existing organization, clear its primary assignment when applicable and revoke roles bound to that organization.

#### Scenario: Leave primary organization

- **WHEN** an operator removes a membership matching the user's primary organization
- **THEN** clear the primary assignment, remove the membership, revoke the organization's scoped roles and audit the revoked roles

#### Scenario: Remove stale assignment

- **WHEN** a role bound to the target organization survives without a membership record
- **THEN** revoke that role and retain global roles and assignments in other organizations

#### Scenario: Repeated removal

- **WHEN** the user and organization exist and the user has already left the organization
- **THEN** return an empty successful response and record the action

#### Scenario: Local transaction fails

- **WHEN** a required role revocation or operator audit fails
- **THEN** roll back the local membership, primary and role changes
