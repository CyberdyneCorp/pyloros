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

### Requirement: Select a component for reviewed source
An administrator SHALL be able to condition component selection on the SHA-256 of the stored hook source encoded as UTF-8. The check and selection SHALL be atomic with respect to edits of that definition.

#### Scenario: Reviewed source is current
- **WHEN** the caller supplies the current source digest and an installed artifact digest
- **THEN** select the requested artifact and include the reviewed source digest in the audit entry when the selection changes

#### Scenario: Source has changed
- **WHEN** the supplied source digest differs from the current source
- **THEN** return HTTP 409, preserve the binding and its audit history, including when the requested artifact is already selected

#### Scenario: Caller omits the source digest
- **WHEN** a caller submits only an artifact digest
- **THEN** apply the existing selection behavior

### Requirement: Bound computation by event size
The worker SHALL grant one million fuel units plus 256 units per admitted event byte, with at most 64 KiB contributing to the allowance.

#### Scenario: Decode a complex admitted context
- **WHEN** a compiled Rust hook reads the event type from a context containing a large unrelated numeric array
- **THEN** allow it to return the event type within the size-adjusted execution budget

#### Scenario: Exhaust the maximum allowance
- **WHEN** a nonterminating component receives a maximum-size event
- **THEN** stop execution and report failure

### Requirement: Assign component delivery ownership
With hooks enabled, PYLOROS_COMPONENT_WORKER_ENABLED SHALL select whether this process consumes queued component deliveries independently of which producer types it dispatches. When omitted, the service SHALL start the worker if any producer is enabled. Disabling hooks globally SHALL suppress the worker.

#### Scenario: Publisher-only replica
- **WHEN** a producer commits an eligible event while local execution is disabled
- **THEN** persist the selected component delivery for another worker

#### Scenario: Dedicated draining worker
- **WHEN** a process enables execution with no producers selected
- **THEN** process due deliveries from the shared queue using their stored component selections

### Requirement: Represent silent successful deliveries in v1 history
The service SHALL record a null output when an automatic component delivery succeeds and returns an empty string. V1 manual results and automatic history SHALL retain up to the first 10,000 Unicode scalar values of successful output, including whitespace.

#### Scenario: Silent registration hook
- **WHEN** a selected registration hook returns success with zero output bytes
- **THEN** its execution history records success with null output and null error
- **AND** manually running the same hook also returns null output

#### Scenario: Successful output exceeds the v1 display limit
- **WHEN** a component returns more than 10,000 characters within the worker output limit
- **THEN** manual results and automatic history contain the first 10,000 characters, including any complete multibyte character at the cutoff
- **AND** the v2 artifact test returns the full guest string

### Requirement: Check a hook port against an offline fixture
The executable SHALL check a local component and JSON event against an expected guest success or guest error with exact text output using the isolated worker, without a database connection.

#### Scenario: A reviewed outcome matches
- **WHEN** the component returns the expected status and exact output for the supplied event
- **THEN** the check exits successfully and prints the SHA-256 of the checked artifact

#### Scenario: A port cannot be verified
- **WHEN** the fixture is invalid, the worker fails, or the guest outcome differs
- **THEN** the check exits unsuccessfully without printing event or output contents

#### Scenario: Review several behaviors for one binding
- **WHEN** an operator supplies multiple event and expected outcome pairs
- **THEN** check each pair in order against one copy of the component and print its digest only after all pairs match
- **AND** a failed case reports its position without disclosing event or output contents

### Requirement: Numeric range during component event admission
The offline fixture checker, artifact dry run and isolated worker SHALL admit otherwise valid bounded JSON events independently of the host floating-point range and forward the original numeric tokens to the component.

#### Scenario: Unrelated field contains a large number
- **WHEN** an admitted event contains a 400-digit integer alongside a string event name
- **THEN** a component that reads only the event name can execute and return that name

#### Scenario: Invalid event contains a large number
- **WHEN** an event containing a large number also contains malformed JSON or exceeds existing event limits
- **THEN** the host refuses the event before component execution

### Requirement: Classify reported timeouts in v1 execution history
An automatic hook delivery that reports an error containing the case-insensitive substring "timeout" SHALL record the v1 execution status "timeout" and preserve the diagnostic. Other reported errors SHALL record the status "failed".

#### Scenario: Component reports an upstream timeout
- **WHEN** a selected component returns an error containing "upstream TIMEOUT"
- **THEN** v1 history reports a timeout with the guest error text and null output

#### Scenario: Successful output mentions a timeout
- **WHEN** a component completes successfully and prints "timeout"
- **THEN** v1 history records success with that output

### Requirement: Inspect pending component deliveries
Operators SHALL be able to read the committed pending delivery count for all events or any set of supported event names. The check SHALL emit a JSON object containing only the pending count and exit with 0 for an empty selection result or 2 for remaining work. Invalid event names and unreadable or missing queue storage SHALL fail without emitting a count.

#### Scenario: Check while the worker is draining
- **WHEN** a selected delivery is delayed or a worker has claimed it without committing removal
- **THEN** include the row once, including when an event name repeats
- **AND** exclude the row once removal commits

#### Scenario: Other producers keep working
- **WHEN** only unrelated deliveries remain
- **THEN** report zero for the selected event types

### Requirement: Run a numeric counter guest
The example counter guest SHALL accept a JSON object with a numeric field named n and output its value plus one followed by a newline. It SHALL preserve integer precision up to 4,300 decimal digits in both input and output and return a guest error for a missing or unsupported value.

#### Scenario: Increment a large decimal integer
- **WHEN** a valid integer exceeds the machine word size and its successor fits the decimal limit
- **THEN** return the exact decimal result

#### Scenario: Missing count
- **WHEN** the event object omits n
- **THEN** return the missing-key diagnostic

### Requirement: Preserve the numeric form in counter results
For finite numeric inputs within the supported range, the counter guest SHALL increment integer tokens using decimal integer arithmetic and tokens containing a fraction or exponent using binary64 arithmetic. Its output SHALL preserve the floating-point representation of integral floating-point results.

#### Scenario: Increment at the binary64 precision boundary
- **WHEN** n is 9007199254740992
- **THEN** the output line is 9007199254740993
- **WHEN** n is 9007199254740992.0
- **THEN** the output line is 9007199254740992.0

#### Scenario: Input uses exponent notation
- **WHEN** n is 1e16
- **THEN** the output line is 1e+16

### Requirement: Read selected fields from wide hook events
The compiled event-name and counter examples SHALL handle supported event objects with thousands of unrelated fields within the worker's existing input and execution limits. The selected field's value SHALL be the last occurrence of its decoded key.

#### Scenario: Ascending unrelated keys
- **WHEN** a valid event contains 5,800 distinct ascending unrelated fields alongside a supported event type and count
- **THEN** each example returns its normal output for the selected field

#### Scenario: Escaped duplicate
- **WHEN** the selected field occurs again using an equivalent escaped key
- **THEN** use the later value and consume the rest of the document

### Requirement: Run a fixed-message guest
The fixed-message example SHALL return the build-time message followed by a newline, limited to 10,000 Unicode scalar values including the newline.

#### Scenario: Execute with unrelated context
- **WHEN** the worker passes an event to the component
- **THEN** the guest emits the configured output independently of the event data

#### Scenario: Message fills the output limit
- **WHEN** the message contains at least 10,000 Unicode scalar values
- **THEN** return its first 10,000 scalar values

### Requirement: Display a hook context using its source-compatible representation
The context display guest SHALL render the supplied object using source-compatible dictionary, list and scalar formatting. It SHALL preserve member insertion order, append a newline and return the first 10,000 Unicode scalar values of that output.

#### Scenario: Display a nested manual context
- **WHEN** a manual invocation supplies `{"z":true,"a":[null,"snow"]}`
- **THEN** the output is `{'z': True, 'a': [None, 'snow']}` followed by a newline

#### Scenario: Repeat an object member
- **WHEN** a manual request contains `{"b":0,"a":1,"b":2}`
- **THEN** the displayed dictionary starts with `'b': 2` followed by `'a': 1`

#### Scenario: Display a dense numeric context
- **WHEN** a reviewed display hook receives thousands of short decimal mantissas with positive or negative exponents in a bounded event
- **THEN** render the source-compatible fixed or scientific notation and return the first 10,000 characters under the standard worker budget

### Requirement: Preserve registration context order after privacy filtering
The registration delivery adapter SHALL supply the permitted fields in their source execution order for new and pending deliveries.

#### Scenario: Registration with personal fields
- **WHEN** the stored delivery includes email and address and the hook still permits personal fields
- **THEN** the component receives email, address, event type and user ID in that order

#### Scenario: Registration with personal fields withheld
- **WHEN** privacy filtering at enqueue or execution withholds personal fields
- **THEN** the component receives only event type followed by user ID

### Requirement: Preserve login context order after privacy filtering
When dispatching a committed login event, the worker SHALL emit the permitted stored fields in source execution order, including when a different version enqueued the event.

#### Scenario: Login with personal fields enabled
- **WHEN** email, user agent and IP were queued and personal fields remain enabled at delivery
- **THEN** emit email, user agent, IP, event type and user ID in that order, retaining any stored null values

#### Scenario: Privacy changes while a login delivery is pending
- **WHEN** personal fields were withheld when the event was queued or the recipient disables them before execution
- **THEN** emit only event type followed by user ID

### Requirement: Preserve displayed entitlement context order
The worker SHALL deliver the stored fields of entitlement grants and revocations in source order for personal and organization owners.

#### Scenario: Display a grant
- **WHEN** a grant delivery is claimed
- **THEN** emit product key, plan, entitlement ID, source, organization ID, event type and user ID in that order with their stored values

#### Scenario: Display a withdrawal
- **WHEN** a revocation delivery is claimed
- **THEN** emit product key, plan, entitlement ID, event type and user ID in that order, preserving a null plan or user ID

### Requirement: Preserve displayed role event order
The worker SHALL deliver role grant and withdrawal fields in the same order for operator and delegated assignments at either hook privacy setting.

#### Scenario: Global assignment
- **WHEN** the worker claims a global role grant or withdrawal
- **THEN** the context contains client ID, role key, event type and user ID in that order

#### Scenario: Organization assignment
- **WHEN** the worker claims an organization role grant or withdrawal
- **THEN** the organization ID appears between the role key and event type

### Requirement: Preserve displayed erasure context order
A deletion hook SHALL receive the event type first and the erased user ID second. These two fields form its complete context at either privacy setting.

#### Scenario: Read execution history after deletion
- **WHEN** a component prints the context of a committed account deletion
- **THEN** its execution history shows the event type followed by the erased subject identifier

### Requirement: Reconcile an interrupted component delivery
For a recorded delivery ID, an operator SHALL be able to inspect queue presence and committed execution status in a single PostgreSQL snapshot.

#### Scenario: Worker stops before committing history
- **WHEN** a worker stops after executing the component and before its completion transaction commits
- **THEN** the delivery remains queued with no committed execution status and another worker can claim it using the pinned component
- **AND** committing the replacement worker's history removes the queue entry and records the outcome under the original delivery ID

#### Scenario: Neither table contains the ID
- **WHEN** the supplied ID has no queue entry and no retained history
- **THEN** report pending as false and execution status as null
