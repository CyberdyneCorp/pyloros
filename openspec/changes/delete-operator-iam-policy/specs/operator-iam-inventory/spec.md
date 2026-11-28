## ADDED Requirements

### Requirement: Delete an unused IAM policy

An authenticated operator SHALL be able to remove an unused IAM policy from the selected provider. The service SHALL report conflicts for policies in use and audit successful deletion.

#### Scenario: Remove an unused policy

- **WHEN** an operator deletes an unused PostgreSQL policy
- **THEN** the policy and its statements are removed, the audit is committed, and the HTTP response is empty

#### Scenario: Policy is in use

- **WHEN** the selected policy is attached to an identity, group or role, or serves as a permission boundary
- **THEN** preserve the policy and its attachments and report the conflict

#### Scenario: Delete a historical policy with non-string rule values

- **WHEN** an authorized operator requests deletion of a policy whose stored rules decode successfully but include historical non-string entries
- **THEN** remove the policy and record the deletion if it is unused
- **AND** return HTTP 409 and preserve the policy if it is still attached
