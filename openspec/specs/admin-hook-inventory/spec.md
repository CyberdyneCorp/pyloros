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
