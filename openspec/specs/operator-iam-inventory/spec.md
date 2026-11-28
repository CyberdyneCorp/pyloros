# operator-iam-inventory Specification

## Purpose

Give operators access to the policy statements and role session limits used by their IAM provider.

## Requirements

### Requirement: List IAM policies

An operator SHALL be able to retrieve the policy inventory from the selected IAM provider, including its total count, policy versions, active status, identifiers and ordered statements.

#### Scenario: Policy contains statements

- **WHEN** an operator lists a policy with statements
- **THEN** include each statement's effect, actions, resources, conditions and statement identifier

### Requirement: List IAM roles

An operator SHALL be able to retrieve IAM roles and the total count from the selected provider.

#### Scenario: Populated inventory

- **WHEN** an operator lists roles
- **THEN** return the role identifiers, names, descriptions, maximum session durations, active status and creation times

#### Scenario: Empty provider inventory

- **WHEN** the provider exposes no roles
- **THEN** return an empty list and zero total

### Requirement: Retrieve an IAM policy

An authenticated operator SHALL be able to retrieve a single policy by its identifier from the configured provider.

#### Scenario: Existing policy

- **WHEN** the operator opens a policy that exists on the selected provider
- **THEN** return its inventory representation with the ordered statements

#### Scenario: Unknown policy

- **WHEN** the identifier is valid and the selected provider has no matching policy
- **THEN** return a missing-resource response

#### Scenario: Provider failure

- **WHEN** the selected provider cannot read its policy catalog
- **THEN** report the provider failure

### Requirement: Read user IAM assignments

An authorized operator SHALL be able to inspect a user's identity and its assignments from the selected IAM provider.

#### Scenario: Membership changes

- **WHEN** an operator reads a user's assignments after a committed membership change
- **THEN** the group list reflects the change while direct policies, roles from active sessions and permission boundary remain independently visible

#### Scenario: Existing user with no IAM identity

- **WHEN** an operator requests the assignments of a PostgreSQL user without an IAM identity
- **THEN** return an empty assignment view

### Requirement: Read user identity token information

An authorized operator SHALL be able to retrieve the user's recorded identity token information and its available on-chain status.

#### Scenario: Stored token metadata

- **WHEN** the selected provider has no current status for the recorded token
- **THEN** expose the recorded token and available metadata to the operator

#### Scenario: Missing user

- **WHEN** the requested user does not exist
- **THEN** return a missing-user response

### Requirement: Manage role policies

An authorized operator SHALL be able to attach a policy to a role and detach it through the selected IAM provider.

#### Scenario: Change permissions for an existing session

- **WHEN** an operator attaches or removes the only role policy granting access to an identity with an active role session
- **THEN** the next access evaluation reflects the change

#### Scenario: Retry a database relationship edit

- **WHEN** an operator repeats a successful edit
- **THEN** the relationship has the requested state and each successful request has its own audit entry

#### Scenario: Failed database audit

- **WHEN** recording the operator action fails
- **THEN** the prior relationship state is preserved

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

### Requirement: Export operator IAM state

An authorized operator SHALL be able to export PostgreSQL IAM state as a versioned JSON document containing policies, groups, roles, identities, permission boundaries and their references.

#### Scenario: Export with chain IAM configured

- **WHEN** an operator exports IAM state while the chain provider is configured
- **THEN** return the stored database entities including their available chain references and the export time

#### Scenario: Audit the disclosure

- **WHEN** an export succeeds
- **THEN** record the operator and inventory counts in the audit without copying identity attributes into the audit metadata

#### Scenario: Audit unavailable

- **WHEN** the export audit cannot be committed
- **THEN** return an error without releasing the export document

### Requirement: Decode documents for policy creation and replacement
Operator policy creation and replacement SHALL use IAM JSON decoding before authorization. An integer literal exceeding 4,300 digits anywhere in the document SHALL return HTTP 400 without creating a policy or advancing its version or writing an operator audit entry.

#### Scenario: A numeric literal occurs in an unused field
- **WHEN** an authorized operator submits an otherwise valid request with an unused field containing a non-finite number
- **THEN** apply the write and expose the committed change through inventory

#### Scenario: Invalid non-finite description
- **WHEN** a validation error would include a non-finite value submitted as the description
- **THEN** return the unhandled HTTP 500 response and preserve the stored state

### Requirement: Decode operator IAM relationship requests
Group policy attachment, user group membership, direct user policy attachment and identity boundary assignment SHALL apply IAM document decoding before operator authentication.

#### Scenario: An extension field contains a non-finite number
- **WHEN** an authorized operator submits a valid relationship identifier and a non-finite literal in an unused field
- **THEN** apply the relationship and record the operator action

#### Scenario: Integer exceeds the document limit
- **WHEN** any integer literal in the submitted document exceeds 4,300 digits
- **THEN** return HTTP 400 without modifying the relationship or appending its audit entry

#### Scenario: A non-finite number is supplied as the identifier
- **WHEN** rendering the identifier validation error would include a non-finite number
- **THEN** return the unhandled HTTP 500 response and preserve the stored relationship

### Requirement: Count overlapping IAM statement positions
An operator SHALL be able to read aggregate counts of affected chain-linked policies, repeated positions within those policies and rows in excess of one per repeated position. The report SHALL include inactive chain-linked policies and return zero counts when all positions are unique.

#### Scenario: Several policies share a position number
- **WHEN** two chain-linked policies each have one statement at position zero
- **THEN** neither policy contributes to the collision counts

#### Scenario: Three rows occupy one position
- **WHEN** an imported policy contains three statements at position zero
- **THEN** that position contributes one affected policy, one repeated position and two excess rows regardless of statement content
