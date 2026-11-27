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
