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

### Requirement: Count repeated stored IAM rule content
The read-only inventory SHALL optionally count chain-linked policies with repeated rule content, repeated groups of rules within those policies and excess rows. Equality SHALL compare SID, effect, actions, resources and conditions using their stored PostgreSQL values independently of row ID and position.

#### Scenario: Import renumbers duplicate rules
- **WHEN** two rules in the same chain-linked policy have identical stored content and different positions
- **THEN** the content inventory reports one affected policy, one repeated rule and one excess row

#### Scenario: Different identifiers or content
- **WHEN** two rules differ in SID, effect, actions, resources or conditions, or belong to different policies
- **THEN** they do not form a repeated group together

### Requirement: Preserve policy directory shape across statement counts
The PostgreSQL policy directory SHALL include each policy in name order, including policies with no statements. Within each policy it SHALL present statements in stored sort order.

#### Scenario: Empty and populated policies share the directory
- **WHEN** an operator lists a directory containing empty and multi-statement policies
- **THEN** the empty policies contain empty statement arrays and the populated policies retain their statement identifiers, effects, actions, resources and conditions

#### Scenario: A stored rule contains an oversized integer in an omitted field
- **WHEN** a policy read encounters an integer wider than 4,300 digits anywhere in a stored statement, including an unused condition field or an action map value
- **THEN** the policy detail and any directory containing that policy return HTTP 500
- **AND** an operator can still retrieve a different policy with valid stored rules

### Requirement: Include ordinary policies in rule collision reports
The operator SHALL be able to request position or rule-content counts across all PostgreSQL IAM policies with `--all-policies`. Without this option the reports SHALL retain their chain-linked scope.

#### Scenario: Competing edits to an ordinary policy
- **WHEN** two distinct rules commit at one position on a policy without a chain identifier
- **THEN** the all-policy position report counts one repeated position and one excess row, and distinct rule content contributes zero repeated rules

#### Scenario: Complete replacement clears local collisions
- **WHEN** an operator replaces the affected statements with uniquely positioned, distinct rules
- **THEN** both all-policy reports cease counting that policy after commit

### Requirement: Validate stored policies for PostgreSQL attachments
Group, role and direct user attachments and identity permission boundaries SHALL validate the stored policy before writing the relationship.

#### Scenario: Historical actions can be loaded
- **WHEN** a stored action array contains a historical numeric entry within the supported integer range
- **THEN** the operator can attach the policy and the successful write records its audit entry

#### Scenario: Stored rules cannot be loaded
- **WHEN** an operator attempts to attach a policy with a nonzero scalar action collection or an integer wider than 4,300 digits
- **THEN** the request returns HTTP 500 and creates neither a relationship nor a success audit entry

### Requirement: Manage ordinary group memberships

An operator SHALL be able to add and remove an identified user from an ordinary IAM group.

#### Scenario: Membership grants and revokes inherited access

- **WHEN** an operator adds a user to a group with a policy that grants access
- **THEN** the group includes that identity once and its applicable grants participate in the next decision
- **WHEN** the membership is removed
- **THEN** subsequent decisions exclude grants from that membership and the shared policy remains attached

#### Scenario: Role-managed group

- **WHEN** an operator requests a membership change on a client-role group through the ordinary group interface
- **THEN** refuse the request and preserve the role assignment

#### Scenario: Failed PostgreSQL audit

- **WHEN** recording the operator action fails
- **THEN** roll back the membership change

#### Scenario: Add overlaps an uncommitted removal
- **WHEN** the adding statement can still see the committed membership while another writer is removing it
- **THEN** treat it as already present, record the operator action, and allow the pending removal to complete

#### Scenario: Concurrent additions encounter the unique constraint
- **WHEN** two writers both see an absent membership and attempt to insert it
- **THEN** the committed addition retains the membership, and a writer rejected by the unique constraint returns HTTP 500 without recording a success audit

#### Scenario: Chain-backed membership
- **WHEN** the group contract confirms the requested mutation and the database commits its operator audit
- **THEN** acknowledge the membership change
- **WHEN** the transaction reverts or confirmation remains uncertain
- **THEN** return an error and omit the success audit

### Requirement: Manage a user's identity token

Authorized operators SHALL be able to retry issuance for a user's wallet and update a minted token's status through the configured provider.

#### Scenario: Retry issuance

- **WHEN** an operator retries issuance for a user with a wallet address and public key
- **THEN** report the provider outcome, persist the outcome on the user, and audit the attempt

#### Scenario: Missing wallet

- **WHEN** a retry targets an existing user without the required wallet or key
- **THEN** report the unsuccessful attempt and record the operator audit

#### Scenario: Change an existing token

- **WHEN** a token status change succeeds
- **THEN** record the change and expose the new status through the user token read

#### Scenario: Mint on the deployed chain

- **WHEN** preparing an identity token mint
- **THEN** send an empty email field to the identity contract

#### Scenario: Read a token using deployment settings

- **WHEN** a user has a token identifier and the identity provider is configured through deployment settings alone
- **THEN** obtain the token status from the deployed identity contract
- **AND** prefer a configured runtime provider when one is available

#### Scenario: Reload the local identity provider

- **WHEN** an operator reapplies blockchain settings while using the local provider
- **THEN** the new provider starts its token sequence at one
- **AND** the user token read continues to expose previously stored metadata

#### Scenario: User metadata changes during a mint retry

- **WHEN** a retry loads user metadata, a concurrent edit commits, and the provider returns an outcome for that retry
- **THEN** persist the retry result against the originally loaded metadata, even when doing so overwrites the intervening metadata edit
- **AND** commit the operator audit and metadata change together

#### Scenario: Audit failure after a local status change

- **WHEN** the provider changes an issued token's status and storing the operator audit fails
- **THEN** roll back the user's metadata update and return an internal error
- **AND** subsequent token reads expose the status already applied by the provider

#### Scenario: Unknown local token

- **WHEN** an operator requests a status change for an integer token identifier absent from the local provider
- **THEN** report an unsuccessful provider outcome and audit the original integer identifier at full precision

#### Scenario: Invalid mint recipient

- **WHEN** a deployed mint retry encounters a malformed hexadecimal recipient before transaction preparation
- **THEN** return the argument failure as the mint outcome and audit it
- **AND** for a full-length address with an invalid checksum, a pending nonce lookup failure takes precedence over the checksum error

#### Scenario: Provider returns a structured error

- **WHEN** the identity provider reports an RPC error during transaction preparation
- **THEN** preserve the provider's field order and integer precision in the operator-facing failure detail

#### Scenario: Provider request fails before submission

- **WHEN** transaction preparation encounters an HTTP refusal or a malformed provider response
- **THEN** report the failed provider outcome to the operator and record the audit
- **AND** include the provider failure detail in the mint retry outcome stored on the user

#### Scenario: Confirm a remote identity token status update

- **WHEN** the configured identity contract confirms the submitted status change
- **THEN** return the transaction hash in the provider's hexadecimal format after committing the user metadata and operator audit
- **WHEN** the transaction is mined but reverts
- **THEN** retain the previous stored status and record the failed outcome with the token identifier and requested status
- **WHEN** the contract confirms the update but the metadata and audit transaction fails to commit
- **THEN** return HTTP 500 and leave the confirmed contract update intact

#### Scenario: Identity status receipt deadline expires

- **WHEN** the provider has accepted a status transaction but its receipt remains pending through the deadline
- **THEN** return HTTP 200 with an unsuccessful result, null transaction hash and empty error string, and record the failed outcome
- **AND** retain the previous stored status even if the transaction later confirms on chain

#### Scenario: Remote mint retry confirms on the identity contract

- **WHEN** a mint retry confirms and the first identity-contract log carries a hexadecimal text token ID
- **THEN** return the confirmed transaction hash and preserve the full integer token ID in the response, user metadata and operator audit
- **AND** accept unsigned 256-bit values represented with surrounding ASCII whitespace, an optional sign, a hexadecimal prefix or valid underscore separators, including signed zero
- **WHEN** the confirmed receipt has no logs
- **THEN** report a successful mint with its transaction hash and a null token ID
- **WHEN** the provider rejects minting or the first log contains an invalid integer
- **THEN** return the failed provider result and persist the mint error with its operator audit

#### Scenario: Stored wallet name cannot be encoded for minting

- **WHEN** an operator retries a remote mint with a stored wallet name
- **THEN** return HTTP 200 with the provider's failed mint result and record its diagnostic in the user metadata and audit
- **AND** reject malformed name syntax before reading the pending nonce, and report encoding failures for accepted names after the nonce lookup and before submission

### Requirement: Create an operator IAM identity

An authorized operator SHALL be able to create an identity using the selected IAM provider and optionally link it to a user in PostgreSQL.

#### Scenario: Create a database identity

- **WHEN** the operator creates an identity with default lifecycle settings
- **THEN** return an active, soulbound identity with HTTP 201 and atomically record its creation audit

#### Scenario: User already has an identity

- **WHEN** the requested user already has an IAM identity in PostgreSQL
- **THEN** return a conflict and preserve the existing identity

#### Scenario: Prepare a chain mint

- **WHEN** identity creation uses the chain provider
- **THEN** encode the owner, public key and metadata URI with an empty email argument

#### Scenario: Confirm a chain identity mint

- **WHEN** a mint confirms and its first contract log identifies the assigned token
- **THEN** return HTTP 201 with the stable identity UUID, the full token identifier and the requested identity attributes
- **AND** interpret the token identifier with the same hexadecimal integer syntax as an identity mint retry
- **AND** record one operator audit and return a null user link for the chain identity
- **WHEN** the provider rejects minting or the receipt yields no usable token identifier
- **THEN** return HTTP 404 and omit the creation audit
- **WHEN** PostgreSQL rejects the audit commit after confirmation
- **THEN** return HTTP 500 and retain the confirmed chain effect
