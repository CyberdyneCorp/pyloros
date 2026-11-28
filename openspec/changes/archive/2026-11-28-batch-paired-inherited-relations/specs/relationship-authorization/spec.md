## ADDED Requirements

### Requirement: Bounded paired inherited lookups

The service SHALL read destinations for an individual node with two eligible inherited proofs in one bounded database statement and evaluate them in declared proof order within the existing snapshot and work budget.

#### Scenario: Second relation contains the grant
- **WHEN** the first inherited relation has no granting destination and sufficient work remains to evaluate a grant through the second relation
- **THEN** the check grants access

#### Scenario: A relation appears twice
- **WHEN** two inherited proofs use one relation with different destination permissions
- **THEN** each proof evaluates the ordered destination prefix with its own permission and consumes its normal work budget
