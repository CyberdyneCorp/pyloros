## ADDED Requirements

### Requirement: Count overlapping IAM statement positions
An operator SHALL be able to read aggregate counts of affected chain-linked policies, repeated positions within those policies and rows in excess of one per repeated position. The report SHALL include inactive chain-linked policies and return zero counts when all positions are unique.

#### Scenario: Several policies share a position number
- **WHEN** two chain-linked policies each have one statement at position zero
- **THEN** neither policy contributes to the collision counts

#### Scenario: Three rows occupy one position
- **WHEN** an imported policy contains three statements at position zero
- **THEN** that position contributes one affected policy, one repeated position and two excess rows regardless of statement content
