## ADDED Requirements

### Requirement: Account for relationships in erasure receipts
Account erasure SHALL report the number of direct account relationships removed and include that count in its audited deletion total.

#### Scenario: Remove direct assignments
- **WHEN** an administrator successfully erases an account with direct relationships
- **THEN** the receipt includes the deleted relationship count and all other accounts keep their assignments

#### Scenario: Erasure fails
- **WHEN** the erasure transaction rolls back
- **THEN** the assignments remain available and no successful erasure is recorded
