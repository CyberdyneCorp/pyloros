## ADDED Requirements

### Requirement: Delete an operator IAM role

An authorized operator SHALL be able to delete a role using the configured IAM provider.

#### Scenario: Delete a role with active sessions

- **WHEN** an operator deletes a PostgreSQL role
- **THEN** return HTTP 204, remove the role and its sessions and policy attachments, preserve the identities and policies, and record the operator action

#### Scenario: Retry a completed deletion

- **WHEN** an operator requests deletion after the role has been removed
- **THEN** return HTTP 404

#### Scenario: Roll back a failed deletion

- **WHEN** the database cannot record the operator audit
- **THEN** preserve the role, its sessions and its policy attachments
