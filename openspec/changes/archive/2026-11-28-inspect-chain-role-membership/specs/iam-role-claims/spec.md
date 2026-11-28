## ADDED Requirements

### Requirement: Inspect a chain role at a canonical block
The operator CLI SHALL check whether the specified group contract lists an identity token in one group at the supplied canonical block hash. A successful JSON report SHALL identify the contract, block hash and decimal group and identity token IDs, and return a membership boolean without exposing other members.

#### Scenario: Provider returns an empty group
- **WHEN** the contract read at the requested block succeeds and the decoded member list is empty
- **THEN** return a successful report with membership false

#### Scenario: Block or result unavailable
- **WHEN** the provider refuses the canonical block lookup or the contract return data cannot be decoded
- **THEN** exit with an error and omit the membership report
