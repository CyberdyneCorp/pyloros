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
