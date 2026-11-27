# admin-user-inventory Specification

## Purpose
Define the administrator-facing account directory, identity summaries and session activity projection.

## Requirements

### Requirement: Inspect accounts as an administrator

The service SHALL permit authorized operators to list users and inspect an individual account using the existing API.

#### Scenario: Search the directory

- **WHEN** an administrator filters the user directory
- **THEN** return the filtered total and a newest-first page, including identity counts and administrator status.
- **WHEN** search text contains wildcard characters
- **THEN** match the text literally in the email or wallet address.

#### Scenario: Inspect an account

- **WHEN** an administrator requests an existing user
- **THEN** return account metadata, linked identity summaries, bootstrap administrator status and the latest session activity.
- **WHEN** the user identifier is unknown
- **THEN** return the established not-found response.

#### Scenario: Protect user information

- **WHEN** the caller lacks administrative access
- **THEN** deny the request before disclosing account data or query validation details.

### Requirement: Inspect a user's active passkeys

The service SHALL allow administrators to read the active passkeys for a specified user across relying parties, independently of the sign-in feature setting.

#### Scenario: Render the inventory

- **WHEN** an authorized operator requests credentials for an existing user
- **THEN** return their active credentials oldest first with the identifier, label, relying party, timestamps and backup flags, and mark the response no-store.

#### Scenario: Distinguish an empty account from a missing one

- **WHEN** the user exists with no active passkeys
- **THEN** return an empty list.
- **WHEN** the user does not exist
- **THEN** return the user-not-found error.

### Requirement: Revoke a user's passkey as an operator

The service SHALL allow an administrator to revoke an active credential belonging to the specified user, including the last credential or one for a different relying party, regardless of the passkey sign-in setting.

#### Scenario: Remove a lost device

- **WHEN** the operator revokes an active credential
- **THEN** return HTTP 204, preserve existing sessions, and commit the credential change with account activity and operator audit records.

#### Scenario: Retry the request

- **WHEN** the credential already appears revoked or belongs to another account
- **THEN** return the missing-credential response.
- **WHEN** two requests independently observe the credential as active before either update commits
- **THEN** both may succeed and each success records its operator action.

#### Scenario: Credential metadata changes concurrently

- **WHEN** an operator observes an active credential and a pending rename or sign-in metadata update commits before the revocation write
- **THEN** the revoked credential retains the metadata the operator observed and the operator audit identifies that credential by its observed label.

### Requirement: Reset a user's authenticator enrollment

The service SHALL let authorized administrators clear a user's TOTP secret and recovery codes for lockout recovery.

#### Scenario: Reset an enrolled authenticator

- **WHEN** an operator resets an existing user's MFA
- **THEN** return HTTP 204, remove the user's TOTP enrollment and recovery codes, and record the operator and prior enrollment state in the audit trails.

#### Scenario: Repeat a reset

- **WHEN** the user already has MFA disabled
- **THEN** clear any pending enrollment secret and recovery codes, return HTTP 204, and audit the reset with the prior disabled state.

#### Scenario: Roll back an incomplete reset

- **WHEN** either audit write fails
- **THEN** roll back the account and recovery-code changes together.

#### Scenario: Continue after account recovery

- **WHEN** the reset commits with a password login challenge outstanding
- **THEN** the former TOTP cannot finish that challenge, existing sessions remain valid, and a fresh password login can proceed without the removed factor.

### Requirement: Manage administrator status

The service SHALL allow authorized operators to grant or revoke administrator access for eligible accounts.

#### Scenario: Change administrator access

- **WHEN** the operator sets a user's administrator status
- **THEN** return the new status and record both the action and previous status. A demotion from a stored administrator role advances the user's token cutoff.

#### Scenario: Protect administrative accounts

- **WHEN** the operator attempts to change their own status or a configuration-managed administrator
- **THEN** refuse the change and record a refusal activity with the reason.

#### Scenario: Audit failure during a change

- **WHEN** a successful status change cannot be audited
- **THEN** roll back the role and token cutoff together.

#### Scenario: Concurrent changes

- **WHEN** overlapping requests each observe a user's previous administrator status
- **THEN** audit each accepted request with the status it observed.

#### Scenario: Invalid role input

- **WHEN** the administrator flag has an invalid type or value
- **THEN** report the invalid field and preserve its submitted JSON value, including integer digits beyond the native machine range.

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

### Requirement: Add an organization membership

An operator SHALL be able to add an existing user to an active organization while preserving their primary organization. The service SHALL return HTTP 201 with a JSON null body on success and atomically record the operator action and membership.

#### Scenario: Repeat an addition

- **WHEN** the user already belongs to the selected organization
- **THEN** retain one membership and audit the accepted request

#### Scenario: Audit failure

- **WHEN** the operator action cannot be recorded
- **THEN** roll back the membership addition

#### Scenario: Overlapping first additions

- **WHEN** two requests have both observed that the membership is absent before either insert commits
- **THEN** commit one addition and its audit, return a server error for the conflicting insert, and allow a later retry to succeed

### Requirement: List the organization catalog

An operator SHALL be able to page through organizations ordered by name with a filtered total. The directory SHALL support filtering by active status, presence of a GitHub login or domain, and literal case-insensitive search across the name, short name, domain and GitHub login.

#### Scenario: Membership picker

- **WHEN** an operator asks for active organizations
- **THEN** return only active entries with their directory fields

#### Scenario: Page beyond the last match

- **WHEN** the requested page is empty
- **THEN** return an empty array and the total matching all filters

### Requirement: Inspect an organization

An operator SHALL be able to retrieve an individual organization's directory record by identifier, including its active status, metadata and timestamps.

#### Scenario: Inactive organization

- **WHEN** an operator retrieves a deactivated organization
- **THEN** return its directory record with the inactive status

#### Scenario: Unknown organization

- **WHEN** an operator requests an identifier with no directory record
- **THEN** return HTTP 404

### Requirement: Create an organization

An operator SHALL be able to create an active organization and obtain its directory record. Creation SHALL validate directory field lengths and string metadata, normalize the stored domain, and atomically record the operator action.

#### Scenario: Directory conflict

- **WHEN** an operator submits a domain in use or a GitHub owner already mapped to an active organization
- **THEN** report a conflict and preserve the existing organization

#### Scenario: Audit failure

- **WHEN** the creation audit fails
- **THEN** roll back the newly inserted organization

#### Scenario: Concurrent organizations with the same name

- **WHEN** operators create organizations with the same display name and distinct mappings
- **THEN** retain separate organizations and their audit records

### Requirement: Edit an organization

An operator SHALL be able to update an organization's directory fields, metadata and active status. The response SHALL include the resulting directory record and the service SHALL audit the accepted fields.

#### Scenario: Metadata edit

- **WHEN** an operator submits metadata entries
- **THEN** replace the submitted values, remove keys given an empty value, and retain other entries from the observed map

#### Scenario: Reactivation conflict

- **WHEN** reactivating an organization would assign a GitHub owner already mapped to an active organization
- **THEN** return a conflict and preserve its stored inactive status

#### Scenario: Audit failure

- **WHEN** the operator audit cannot be recorded
- **THEN** roll back the directory edit

### Requirement: Deactivate an organization

An operator SHALL be able to deactivate an organization while preserving membership references and recording the action atomically.

#### Scenario: Retire an active organization

- **WHEN** an operator deletes an existing organization
- **THEN** return an empty 204 response with the JSON content type and exclude the organization from active membership results

#### Scenario: Retry a deactivation

- **WHEN** an operator repeats the request for an inactive organization with unchanged directory data
- **THEN** record the accepted action and return 204 while preserving the directory update timestamp

#### Scenario: Audit failure

- **WHEN** the action cannot be recorded
- **THEN** roll back the directory update

### Requirement: Manage primary organization

An operator SHALL be able to set or clear the primary organization of an existing user. The operator audit, primary organization and explicit membership changes SHALL commit together.

#### Scenario: Assign active organization

- **WHEN** the operator assigns an active organization
- **THEN** record it as primary, ensure the user has an explicit membership and return an empty 204 response

#### Scenario: Clear primary organization

- **WHEN** the operator submits an assignment document with an omitted or null organization identifier
- **THEN** clear the primary organization and retain existing explicit memberships

#### Scenario: Assignment rejected

- **WHEN** the requested organization is missing or inactive
- **THEN** return a missing-resource response and preserve the user's previous assignment
