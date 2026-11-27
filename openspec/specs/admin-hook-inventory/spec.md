# admin-hook-inventory Specification

## Purpose
Let administrators inspect stored hook configuration and execution outcomes during and after a backend migration.

## Requirements

### Requirement: Inspect installed hooks and recorded runs
The service SHALL allow administrators to read installed hook definitions and the recorded executions associated with a hook.

#### Scenario: Inspect a disabled hook
- **WHEN** an administrator retrieves an inactive hook
- **THEN** return its saved definition, execution settings and privacy preference

#### Scenario: Page execution history
- **WHEN** an administrator requests a page of historical executions
- **THEN** return the latest runs first with the total count across pages

#### Scenario: Remove administrative access
- **WHEN** an operator loses administrator privileges
- **THEN** subsequent reads using the existing session are denied

### Requirement: Validate operator hook source
The service SHALL accept source validation requests from authorized administrators and report the applicable syntax or restricted-language diagnostic without executing the source.

#### Scenario: Valid source
- **WHEN** submitted source satisfies the authoring rules
- **THEN** return a positive validation result and an empty diagnostic

#### Scenario: Rejected source
- **WHEN** parsing or an authoring restriction rejects source
- **THEN** return a negative validation result with the diagnostic and preserve stored hooks and bindings

#### Scenario: Compiler context error
- **WHEN** a parsed module would fail during compilation because of an invalid declaration or control-flow context
- **THEN** report an internal server error without executing the module

#### Scenario: Worker unavailable
- **WHEN** the source-validation worker cannot accept or complete a request
- **THEN** return a service unavailable response and preserve stored hooks

#### Scenario: Source admission limits
- **WHEN** the HTTP envelope exceeds 64 MiB
- **THEN** return HTTP 413 before invoking the worker

#### Scenario: Large module
- **WHEN** an authorized operator submits a valid module larger than 2 MiB within the accepted request envelope
- **THEN** validate the entire module and return the result

### Requirement: Author hook definitions
The service SHALL accept authorized creation and editing of hook definitions, validate submitted source without executing it, and record each successful operation in the audit history.

#### Scenario: Create a definition
- **WHEN** an operator supplies an available name, supported event and acceptable source
- **THEN** return the persisted definition with its identifier and execution settings

#### Scenario: Partially edit a definition
- **WHEN** an operator updates selected settings on an existing hook
- **THEN** apply supplied non-null fields and preserve the other settings

#### Scenario: Reject invalid input
- **WHEN** an input violates the field schema, the source policy or name uniqueness
- **THEN** return the applicable validation or conflict response and preserve the stored definition

#### Scenario: Audit failure
- **WHEN** recording the operator action fails
- **THEN** roll back the mutation and preserve the previous component selection

#### Scenario: Concurrent creation with the same name
- **WHEN** two requests both observe that a name is available and attempt to insert it
- **THEN** commit one definition and audit entry, and return an internal error for the failed insertion
