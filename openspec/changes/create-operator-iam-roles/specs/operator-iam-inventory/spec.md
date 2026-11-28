## ADDED Requirements

### Requirement: Create an operator IAM role

An authorized operator SHALL be able to create a named role with a maximum session duration and an optional description using the configured IAM provider.

#### Scenario: Successful database creation

- **WHEN** an operator creates a role using PostgreSQL
- **THEN** return the new active role with HTTP 201, expose it in inventory and record the operator action atomically

#### Scenario: Failed audit

- **WHEN** the database cannot record the creation audit
- **THEN** the role and its audit are both absent

#### Scenario: Confirm creation through the policy contract

- **WHEN** the configured policy contract confirms a role creation and its first log identifies the assigned role in the reference provider’s hexadecimal text format
- **THEN** verify the log belongs to that contract, transaction and block, commit a creation audit for the derived role UUID and return HTTP 201 with the submitted session duration

#### Scenario: Confirmed transaction without a recoverable role ID or audit

- **WHEN** the confirmed receipt lacks a verifiable role ID or PostgreSQL rejects the audit commit
- **THEN** return HTTP 500 without a successful audit and preserve the on-chain effect
