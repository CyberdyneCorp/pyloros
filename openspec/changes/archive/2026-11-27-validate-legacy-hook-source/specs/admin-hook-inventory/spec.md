## ADDED Requirements

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
- **WHEN** the decoded UTF-8 source exceeds 2 MiB or the HTTP envelope exceeds 64 MiB
- **THEN** return HTTP 413 before invoking the worker
