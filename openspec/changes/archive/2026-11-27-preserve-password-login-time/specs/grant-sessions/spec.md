## ADDED Requirements

### Requirement: Distinguish session persistence times

The service SHALL record session creation and initial activity at the PostgreSQL transaction timestamp and timestamp the initial refresh record after the session insert succeeds.

#### Scenario: Delayed session write

- **WHEN** contention delays persistence after the credential issue time
- **THEN** the stored refresh record reflects its registration time and the signed credential retains its original lifetime
