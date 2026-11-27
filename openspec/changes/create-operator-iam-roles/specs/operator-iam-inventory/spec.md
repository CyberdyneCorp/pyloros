## ADDED Requirements

### Requirement: Create an operator IAM role

An authorized operator SHALL be able to create a named role with a maximum session duration and an optional description using the configured IAM provider.

#### Scenario: Successful database creation

- **WHEN** an operator creates a role using PostgreSQL
- **THEN** return the new active role with HTTP 201, expose it in inventory and record the operator action atomically

#### Scenario: Failed audit

- **WHEN** the database cannot record the creation audit
- **THEN** the role and its audit are both absent
