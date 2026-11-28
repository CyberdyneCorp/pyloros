## ADDED Requirements

### Requirement: Manage direct user policy assignments

An authorized operator SHALL be able to attach and detach a policy directly on a user's IAM identity.

#### Scenario: Attach an applicable grant

- **WHEN** an operator attaches an applicable allow policy to an identity
- **THEN** the user detail view lists the direct assignment once and access evaluation considers its grant

#### Scenario: Remove a direct assignment

- **WHEN** an operator detaches a direct policy
- **THEN** the direct assignment disappears and access evaluation continues to consider independent grants and the existing permission boundary

#### Scenario: Failed PostgreSQL audit

- **WHEN** recording the operator action fails
- **THEN** the direct assignment and its effective access retain their previous state

#### Scenario: Confirm a direct policy change on chain

- **WHEN** an operator attaches or detaches a policy for a user with a chain identity
- **THEN** confirm the submitted transaction on the configured policy contract before committing the operator audit and returning success
- **AND** if PostgreSQL rejects the audit commit, return HTTP 500 and retain the confirmed on-chain change

#### Scenario: PostgreSQL writers overlap on one direct grant

- **WHEN** an attachment sees a committed link while another writer is removing it
- **THEN** audit the attachment without reinserting the link
- **WHEN** two first attachments both see an absent link
- **THEN** the first commit succeeds and the conflicting insert fails without a second success audit
