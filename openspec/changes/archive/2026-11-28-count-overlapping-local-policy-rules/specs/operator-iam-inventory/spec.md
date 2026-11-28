## ADDED Requirements

### Requirement: Include ordinary policies in rule collision reports
The operator SHALL be able to request position or rule-content counts across all PostgreSQL IAM policies with `--all-policies`. Without this option the reports SHALL retain their chain-linked scope.

#### Scenario: Competing edits to an ordinary policy
- **WHEN** two distinct rules commit at one position on a policy without a chain identifier
- **THEN** the all-policy position report counts one repeated position and one excess row, and distinct rule content contributes zero repeated rules

#### Scenario: Complete replacement clears local collisions
- **WHEN** an operator replaces the affected statements with uniquely positioned, distinct rules
- **THEN** both all-policy reports cease counting that policy after commit
