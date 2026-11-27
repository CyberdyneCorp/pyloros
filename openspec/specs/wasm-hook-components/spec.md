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
