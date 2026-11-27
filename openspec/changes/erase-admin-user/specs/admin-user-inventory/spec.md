## ADDED Requirements

### Requirement: Erase an account as an administrator

The service SHALL allow an authorized operator to erase an existing account and report the records deleted, pseudonymised and retained.

#### Scenario: Erase linked records

- **WHEN** the operator deletes an account
- **THEN** collect its linked identifiers, revoke sessions, erase related records and report counts by table. Report applicable external processors.

#### Scenario: Preserve audit integrity

- **WHEN** retained activity identifies the erased subject
- **THEN** pseudonymise its identifying fields and reseal the record. Record the erasure without reintroducing the erased account's email into operator audit metadata.

#### Scenario: Roll back an incomplete erasure

- **WHEN** an audit write or required webhook enqueue fails
- **THEN** roll back the erasure and session revocation.

#### Scenario: Active deletion hook during migration

- **WHEN** the deployment enables hooks and an active account-deletion hook requires a dispatcher that is unavailable
- **THEN** return HTTP 503 before changing the account or recording a successful deletion.
