## ADDED Requirements

### Requirement: Group membership checks on direct-only objects
When a traversal batch contains at least eight objects of the same type and permission governed by a single direct rule, the evaluator SHALL check the eligible objects for membership together within its existing client snapshot and work budget.

#### Scenario: A team grants access
- **WHEN** the account is assigned the direct relation on any team within the eligible batch prefix
- **THEN** return an allowed decision

#### Scenario: Budget ends before the granting team
- **WHEN** no eligible team grants access and remaining teams cannot be checked within the budget
- **THEN** report an unavailable decision unless another eligible path proves access
