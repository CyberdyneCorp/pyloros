## ADDED Requirements

### Requirement: Open the permission snapshot in one statement
The permission check SHALL begin its PostgreSQL transaction in read-only repeatable-read mode with one statement.

#### Scenario: Prepare an inherited check
- **WHEN** a check begins evaluating a permission through a parent
- **THEN** the initial transaction statement establishes both isolation and read-only mode before any decision inputs are read
