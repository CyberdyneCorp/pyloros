## ADDED Requirements

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
