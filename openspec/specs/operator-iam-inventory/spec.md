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
