## ADDED Requirements

### Requirement: Bound computation by event size
The worker SHALL grant one million fuel units plus 256 units per admitted event byte, with at most 64 KiB contributing to the allowance.

#### Scenario: Decode a complex admitted context
- **WHEN** a compiled Rust hook reads the event type from a context containing a large unrelated numeric array
- **THEN** allow it to return the event type within the size-adjusted execution budget

#### Scenario: Exhaust the maximum allowance
- **WHEN** a nonterminating component receives a maximum-size event
- **THEN** stop execution and report failure
