## ADDED Requirements

### Requirement: Manage the policies attached to a group

An authorized operator SHALL be able to attach and detach an existing IAM policy on a group.

#### Scenario: Group member inherits a grant

- **WHEN** an operator attaches an applicable allow policy to a group
- **THEN** the group inventory includes the attachment once and access evaluation considers the policy for group members

#### Scenario: Remove the only grant

- **WHEN** an operator detaches the only policy granting a member access
- **THEN** the next access check denies that access and the policy and membership still exist

#### Scenario: PostgreSQL audit failure

- **WHEN** recording an attachment or detachment fails
- **THEN** the transaction preserves the previously committed relationships

#### Scenario: Attaching a policy while group deletion commits

- **WHEN** a PostgreSQL attachment request waits for a deletion of its target group and that deletion commits
- **THEN** Pyloros returns HTTP 404, creates no attachment, and records no successful attachment audit

#### Scenario: Detaching a policy while group deletion commits

- **WHEN** a detachment waits for a group deletion that removes its existing attachment and commits
- **THEN** the detachment returns HTTP 200 and records one detachment audit
- **AND** subsequent group inventory omits the group and permission checks deny access previously granted solely through that attachment

#### Scenario: Confirm a chain-backed group policy change
- **WHEN** an operator attaches or detaches a policy through the group contract
- **THEN** verify the receipt for the submitted transaction and configured group contract before committing the operator audit and returning success
- **WHEN** PostgreSQL rejects the audit commit after confirmation
- **THEN** return HTTP 500 and leave the confirmed group policy change observable on chain

#### Scenario: Concurrent PostgreSQL group policy changes
- **WHEN** an attachment sees an existing link while a peer detachment is uncommitted
- **THEN** audit the attachment without reinserting the link and allow the detachment to finish
- **WHEN** two first attachments both see an absent link
- **THEN** a unique constraint rejection rolls back the losing attachment and its audit
