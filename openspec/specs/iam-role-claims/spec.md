# iam-role-claims Specification

## Purpose
Use the configured IAM authority to resolve user roles and give administrators a way to inspect, update and check the chain provider.

## Requirements

### Requirement: Authoritative membership for role claims

The service SHALL derive user role claims from groups reported by the active IAM backend and restrict organization roles to active memberships.

#### Scenario: Conflicting membership sources

- **WHEN** the active backend returns an empty membership and a secondary store retains a role
- **THEN** the service emits empty role assignments for the user

#### Scenario: Catalog contains a member without an exported identity

- **WHEN** a group names the linked token but the authority exports no identity for that token
- **THEN** it confers no role on the user

#### Scenario: Authority is unavailable

- **WHEN** a role lookup fails during first-party token issuance
- **THEN** the issued token omits its role claims

#### Scenario: Organization membership removed

- **WHEN** a group identifies an organization role and the user no longer has active membership there
- **THEN** the role is excluded from the user's assignments

#### Scenario: A session outlives a provider switch

- **WHEN** the configured authority changes after a user signs in
- **THEN** profile reads, token introspection, and refreshed credentials use the authority selected at the time of the operation

#### Scenario: Failed lookup during delegated issuance

- **WHEN** the active authority cannot resolve membership during authorization-code redemption or refresh
- **THEN** credentials omit unresolved role and derived permission claims, and introspection omits those claims while reporting the valid token as active

#### Scenario: Failed lookup during a profile read

- **WHEN** an authenticated user requests their profile during an IAM lookup failure
- **THEN** the profile returns null for both global and organization roles

#### Scenario: The authority recovers

- **WHEN** a subsequent lookup succeeds and reports no memberships
- **THEN** role-bearing responses return empty global and organization assignments for the user

### Requirement: Administrative visibility of the chain configuration

The service SHALL allow a current administrator to inspect the process-local chain configuration. A read SHALL report the enablement flag, endpoint, contract addresses, signer address, key presence and configuration completeness. Signing credentials SHALL remain private.

#### Scenario: Fresh process

- **WHEN** an administrator reads the chain settings before a runtime update
- **THEN** the configuration is disabled with no key or addresses set

#### Scenario: Replaced signer

- **WHEN** an operator replaces the signing key with a nonempty unparseable key
- **THEN** subsequent settings reads report key presence and a null signer address

### Requirement: Administrator chain health read

The service SHALL allow an authenticated administrator to check whether the selected chain provider can answer a block-number request. The response SHALL report enablement, availability, endpoint, identity contract address and any provider error. A configured runtime provider takes precedence over the deployment provider. The check SHALL complete within five seconds of starting the RPC operation.

#### Scenario: No configured provider

- **WHEN** no chain provider is configured
- **THEN** the check reports disabled and unavailable with null endpoint and contract address

#### Scenario: Recovery

- **WHEN** the provider answers successfully after an earlier RPC error
- **THEN** the next health read reports available and clears the error

#### Scenario: Provider request fails

- **WHEN** the block-number request encounters a transport failure
- **THEN** retry within the overall health deadline and report the failure detail if the provider remains unavailable

#### Scenario: Malformed provider response

- **WHEN** the provider returns malformed JSON
- **THEN** report the parse diagnostic and keep the selected endpoint and contract in the health response

#### Scenario: Health provider response identifier

- **WHEN** the provider answers the informational block-number request with a numeric response identifier or its decimal string representation
- **THEN** determine availability from its response and report malformed envelopes with a diagnostic

#### Scenario: Large successful reply

- **WHEN** a valid block-number response includes large extension fields
- **THEN** report availability from the block result within the health deadline

#### Scenario: Provider hostname refuses connections

- **WHEN** each resolved address of a directly connected provider refuses the final health request
- **THEN** include the hostname, port and individual connection failures in the operator diagnostic

### Requirement: Operator chain settings updates

The service SHALL accept partial updates from an authenticated administrator and report the resulting signer address. The audit record SHALL contain sorted names of submitted settings and secret fields. Credentials SHALL stay out of the audit record and the success response.

#### Scenario: Mnemonic and raw key submitted together

- **WHEN** the submitted mnemonic is valid
- **THEN** the signer is derived from the Ethereum account at the requested index, with index zero as the default

#### Scenario: Invalid mnemonic

- **WHEN** mnemonic derivation fails
- **THEN** the service responds with HTTP 400, preserves the prior configuration and writes no settings-change audit event

#### Scenario: Unspecified and null fields

- **WHEN** an operator supplies a partial update
- **THEN** omitted and null values retain their previous settings

### Requirement: Recognize stored organization role identifiers

The role group reader SHALL recognize a stored organization UUID whose hexadecimal digits have noncanonical hyphen placement.

#### Scenario: Existing organization assignment

- **WHEN** the group suffix contains all 32 UUID digits with an irregular hyphen position
- **THEN** the assignment resolves to the corresponding organization and can be removed through role administration

### Requirement: Inspect user role assignments

An operator SHALL be able to inspect an existing user’s stored global and organization role assignments through the admin API. The inventory SHALL retain duplicate assignments and include assignments to inactive organizations.

#### Scenario: Grouped inventory

- **WHEN** the user has both global and organization assignments
- **THEN** return global roles and a map of organization IDs to roles, sorted within each list by client and role key

#### Scenario: Missing chain identity link

- **WHEN** chain IAM is active and the user has no linked chain token
- **THEN** return an empty inventory without contacting the provider

### Requirement: Grant a client role to a user

An operator SHALL be able to grant a global or organization-scoped catalog role to a PostgreSQL user. A scoped grant SHALL require active organization membership. Repeated grants SHALL preserve a single membership and record each successful operation.

#### Scenario: First assignment

- **WHEN** a target has no PostgreSQL IAM identity
- **THEN** create the identity with the membership and audit both actions atomically

#### Scenario: Subscribed role grant

- **WHEN** an active webhook subscription includes role grants and webhooks are enabled
- **THEN** persist a delivery containing the target user, client, role and optional organization in the assignment transaction

### Requirement: Revoke a user client role

An operator SHALL be able to revoke one user assignment from a PostgreSQL role. A scoped revocation SHALL work after organization membership ends and SHALL preserve the global assignment. Successful removal, audit and subscribed webhook deliveries SHALL commit atomically.

#### Scenario: Organization group absent

- **WHEN** the global catalog role exists but the requested organization group has never existed
- **THEN** return an empty success, audit the operation and omit event delivery

#### Scenario: Repeat an existing group revocation

- **WHEN** an operator repeats revocation for an existing group and user identity
- **THEN** return an empty success and emit the subscribed role-revoked event

### Requirement: Measure stored assignments under overlapping registered namespaces
The operator command SHALL optionally report aggregate counts of candidate PostgreSQL role groups, populated candidate groups, their membership rows and distinct member identities. A candidate group has a name beginning with `rp:`, the longer ID in an overlapping registered pair and a literal colon. The report SHALL include inactive registrations and read the counts from one committed snapshot.

#### Scenario: Multiple prefixes match one group
- **WHEN** a stored group name matches two overlapping registered namespaces
- **THEN** count that group once and count each of its memberships once

#### Scenario: Identity belongs to multiple candidate groups
- **WHEN** one identity has membership in two candidate groups
- **THEN** count both membership rows and one distinct identity

#### Scenario: No stored assignments
- **WHEN** candidate groups exist but all are empty
- **THEN** report their count with zero populated groups, membership rows and identities

### Requirement: Select webhook recipients on each role change
With webhooks enabled, an operator or delegated client role mutation that emits an event SHALL persist a single event shared by one delivery per active subscription matching its type. When none match, the mutation SHALL commit its role and audit effects without creating an event or delivery.

#### Scenario: Filter changes before a repeated grant
- **WHEN** two subscriptions match a grant, one switches to revocations, and a writer repeats the grant
- **THEN** the first event retains both delivery records and the new event has only the remaining grant subscriber, with one assigned role and an audit entry for each grant

#### Scenario: Subscriptions are disabled between writes
- **WHEN** the grant subscriber is disabled, the role is revoked, and the revocation subscriber is disabled before the next grant
- **THEN** the revocation has one delivery to its subscriber and the next grant succeeds without creating a webhook event

### Requirement: Coordinate role assignment preparations across replicas
Operator and delegated chain-backed role edits SHALL hold the shared PostgreSQL signer lock throughout unsigned membership transaction preparation. A grant that prepares creation of a missing organization role group SHALL use the same lock.

#### Scenario: Concurrent addition and removal
- **WHEN** separate replicas prepare a grant and revocation using the same signer
- **THEN** the second preparation waits to read the pending nonce until the first preparation ends

#### Scenario: Missing scoped group
- **WHEN** an eligible scoped grant needs a new group while a role transaction is in preparation for the same signer
- **THEN** wait for that preparation before reading the pending nonce for group creation
