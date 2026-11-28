## ADDED Requirements

### Requirement: Check component binding coverage for one event
The operator SHALL be able to limit the read-only inventory and its coverage exit code to a single supported hook event.

#### Scenario: Check a producer before switching it
- **WHEN** the operator supplies a supported event name to the binding check
- **THEN** report only definitions for that event, in hook ID order, and count only its active unbound definitions
- **AND** return success for a supported event with no definitions

#### Scenario: Mistyped event name
- **WHEN** the operator supplies an unknown event or malformed arguments to the binding check
- **THEN** exit with a usage error distinct from incomplete binding coverage and emit no inventory
