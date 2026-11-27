# wasm-hook-components Specification

## Purpose
Define how administrators check a hook artifact against the published WebAssembly interface before installation.

## Requirements

### Requirement: Validate a versioned hook component
The service SHALL allow a current administrator to submit a WebAssembly component for side-effect-free validation against the published hook interface.

#### Scenario: Identify a compatible artifact
- **WHEN** the component validates and exports the supported synchronous event handler
- **THEN** return the ABI identifier, size in bytes and SHA-256 of the uploaded artifact

#### Scenario: Reject an unsupported capability
- **WHEN** the component requests a host import outside the supported profile
- **THEN** report the incompatibility and leave installed hooks unchanged

#### Scenario: Reject a malformed artifact
- **WHEN** the binary, function bodies, or exported interface do not validate
- **THEN** report the reason without executing guest code

### Requirement: Stage immutable hook components
The service SHALL allow current administrators to install validated component bytes and retrieve them by their SHA-256 digest.

#### Scenario: Install or retry a component
- **WHEN** authorized uploads contain the same compatible bytes
- **THEN** atomically persist one artifact and one operator audit entry, return its identity to every caller, and leave active hooks unchanged

#### Scenario: Retrieve staged bytes
- **WHEN** an administrator requests an existing artifact by digest
- **THEN** return its exact bytes as application/wasm

#### Scenario: Reject an invalid component
- **WHEN** installation fails the component validation checks
- **THEN** return the validation failure and persist no artifact

### Requirement: Dry-run a staged component
The service SHALL allow an administrator to run a staged component with supplied event JSON using a fresh, resource-limited worker.
#### Scenario: Successful handler
- **WHEN** the staged component returns a successful string result
- **THEN** return that output without activating the hook or delivering a production event
#### Scenario: Handler failure or exhausted budget
- **WHEN** the guest returns an error, traps, exceeds its resource limits or times out
- **THEN** report the failed dry run and permit subsequent runs in a fresh worker

### Requirement: Select a staged version for a hook
The service SHALL allow a current administrator to read, set, replace or release the component version selected for a stored hook.
#### Scenario: Select a staged version
- **WHEN** an administrator selects an existing artifact for a hook
- **THEN** atomically save the binding and audit the old and new digests while preserving the hook's settings
#### Scenario: Retry a completed update
- **WHEN** the selected digest already matches the requested value or an already empty binding is released
- **THEN** return the current binding without an additional audit entry
#### Scenario: Reject an unknown version
- **WHEN** the requested digest has no staged artifact
- **THEN** return a missing-artifact error and preserve the prior binding

### Requirement: Deliver committed store entitlement changes
The service SHALL dispatch store grant and revocation events to the version selected for each active hook when delivery is enabled.

#### Scenario: Grant or revoke
- **WHEN** a store entitlement transition commits
- **THEN** run each selected component with the allowed event fields and persist its result in hook execution history

#### Scenario: Rollback or duplicate notification
- **WHEN** a billing transaction rolls back or a previously processed notification is replayed
- **THEN** produce no additional delivery

#### Scenario: Missing selection or worker outage
- **WHEN** a matching active hook has no selected version
- **THEN** leave the billing mutation retryable
- **WHEN** an execution worker becomes temporarily unavailable after commit
- **THEN** retain the delivery for retry with its original artifact version

### Requirement: Deliver administrator entitlement changes
The service SHALL queue one delivery per matching active component hook for each committed administrator grant or withdrawal when operator entitlement dispatch is enabled.

#### Scenario: Personal or organization ownership
- **WHEN** a grant is issued or reactivated
- **THEN** deliver the entitlement id, product, plan, source and organization, with the subject user id for a personal grant and a null user id for an organization grant

#### Scenario: Repeated withdrawal
- **WHEN** an administrator withdraws an existing entitlement, including one already withdrawn
- **THEN** deliver a revocation with its subject, entitlement id, product and plan

#### Scenario: Change rolls back
- **WHEN** the grant, withdrawal or its administrator audit record cannot commit
- **THEN** leave no queued delivery for that operation

### Requirement: Deliver PostgreSQL role changes
The service SHALL deliver a version-pinned event for each accepted PostgreSQL role assignment or withdrawal when role hook dispatch is enabled.

#### Scenario: Administrator or delegated change
- **WHEN** an authorized writer grants or revokes a role
- **THEN** deliver the event type, target user, resolved client and role key, and include the organization id for a scoped assignment

#### Scenario: Repeat assignment or withdrawal
- **WHEN** the membership already has the requested state and the write succeeds
- **THEN** queue an event for that accepted write

#### Scenario: Remove organization membership
- **WHEN** removing a user from an organization withdraws scoped roles
- **THEN** queue a revocation for each withdrawn assignment in the same transaction

#### Scenario: Roll back the role write
- **WHEN** the enclosing operation fails to commit
- **THEN** expose neither a queued delivery nor an execution record for that operation

### Requirement: Deliver committed account registrations
The service SHALL queue registration events for accounts created by self-registration, administrator creation, CSV import or service-client invitation when registration dispatch is enabled.

#### Scenario: Per-recipient privacy
- **WHEN** a new account commits
- **THEN** deliver its user id and event type to each selected active hook, adding normalized email and public wallet address only for recipients opted in at enqueue and execution

#### Scenario: Existing or rolled back account
- **WHEN** a request creates no account or its transaction rolls back
- **THEN** produce no registration delivery

### Requirement: Deliver completed interactive login events
When interactive login dispatch is enabled, the service SHALL enqueue one event per active bound recipient in the same transaction as a new interactive session.

#### Scenario: Completed login
- **WHEN** password, passkey, or second-factor verification completes interactive login
- **THEN** each recipient receives the event type and user ID, with email, IP and user agent only for recipients opted in at enqueue and execution

#### Scenario: Login does not commit
- **WHEN** login fails, awaits a second factor, or its session transaction rolls back
- **THEN** the worker receives no event from that attempt

### Requirement: Deliver account erasure to bound components
The service SHALL deliver committed account erasures to selected active deletion hooks when erasure dispatch is enabled.

#### Scenario: Account removed
- **WHEN** an administrator commits an erasure
- **THEN** each selected recipient receives only the event type and erased user ID, irrespective of its privacy settings, and execution history records that ID

#### Scenario: Outstanding deliveries
- **WHEN** the account is erased with older personal deliveries queued or completing
- **THEN** discard pending account deliveries and remove their execution history

#### Scenario: Erasure rolled back
- **WHEN** the transaction aborts
- **THEN** retain the account and its prior deliveries and enqueue no deletion event

### Requirement: Deliver OAuth user grant login events
When login dispatch is enabled, the service SHALL deliver one login event per selected recipient for each committed authorization-code or approved device-code session, using the token request origin and the interactive login privacy rules.

#### Scenario: Grant remains retryable
- **WHEN** dispatch cannot select all active recipients or the transaction fails
- **THEN** roll back the session, grant consumption and deliveries

#### Scenario: Unsupported ID token signing
- **WHEN** a user grant commits a session under HS256 and cannot issue the requested ID token
- **THEN** consume the grant without binding a session ID to the code, retain the success audit and login deliveries and return the signing error

#### Scenario: No new user session
- **WHEN** a client refreshes tokens, polls a pending device code or replays a consumed code
- **THEN** enqueue no login event

### Requirement: Invalidate a component selection on source edits
The service SHALL clear a hook’s selected component when any writer commits a change to its stored source.

#### Scenario: Committed edit
- **WHEN** source text changes for a bound hook
- **THEN** clear its binding in the edit transaction and require selection before dispatching future events to that hook
- **AND** retain the pinned versions of previously queued deliveries

#### Scenario: Settings change or aborted edit
- **WHEN** a writer updates settings without changing source, resubmits identical source or rolls back a source edit
- **THEN** preserve the hook’s prior selection
