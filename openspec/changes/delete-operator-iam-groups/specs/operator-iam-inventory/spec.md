## ADDED Requirements

### Requirement: Delete an ordinary IAM group

An authorized operator SHALL be able to delete an ordinary group from the selected IAM provider.

#### Scenario: Populated PostgreSQL group

- **WHEN** an operator deletes a group with members and attached policies
- **THEN** remove the group and its links, audit the action and preserve the identities and policies

#### Scenario: Client-role group

- **WHEN** an operator attempts to delete a group reserved for a client role
- **THEN** refuse the mutation and preserve the group

#### Scenario: Failed audit

- **WHEN** a PostgreSQL group deletion cannot be audited
- **THEN** roll back the deletion and preserve access through the group

#### Scenario: A deletion is rejected at commit while a second operator waits

- **WHEN** PostgreSQL explicitly rejects the deletion transaction and a second writer is waiting to detach a policy or delete the same group
- **THEN** Pyloros returns HTTP 500 for the rejected deletion and writes no deletion audit for it
- **AND** prior to commit, readers can still list the group and evaluate access through its attached policy
- **AND** the waiting writer can commit against the restored group and record its own audit

#### Scenario: Read access after the waiting writer commits

- **WHEN** the waiting writer removes the only policy granting an action, or deletes the group providing it
- **THEN** subsequent evaluations deny the action and the policy itself remains available

#### Scenario: Confirm deletion on the group contract

- **WHEN** an operator deletes an ordinary chain-backed group
- **THEN** Pyloros verifies successful execution on the configured group contract before recording the deletion audit and returning HTTP 204
- **AND** if PostgreSQL rejects the audit commit after confirmation, Pyloros returns HTTP 500 and the group remains deleted on chain
