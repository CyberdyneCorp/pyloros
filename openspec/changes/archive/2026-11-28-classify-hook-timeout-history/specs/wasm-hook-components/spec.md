## ADDED Requirements

### Requirement: Classify reported timeouts in v1 execution history
An automatic hook delivery that reports an error containing the case-insensitive substring "timeout" SHALL record the v1 execution status "timeout" and preserve the diagnostic. Other reported errors SHALL record the status "failed".

#### Scenario: Component reports an upstream timeout
- **WHEN** a selected component returns an error containing "upstream TIMEOUT"
- **THEN** v1 history reports a timeout with the guest error text and null output

#### Scenario: Successful output mentions a timeout
- **WHEN** a component completes successfully and prints "timeout"
- **THEN** v1 history records success with that output
