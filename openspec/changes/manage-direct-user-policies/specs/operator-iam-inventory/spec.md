## ADDED Requirements

### Requirement: Manage direct user policy assignments

An authorized operator SHALL be able to attach and detach a policy directly on a user's IAM identity.

#### Scenario: Attach an applicable grant

- **WHEN** an operator attaches an applicable allow policy to an identity
- **THEN** the user detail view lists the direct assignment once and access evaluation considers its grant

#### Scenario: Remove a direct assignment

- **WHEN** an operator detaches a direct policy
- **THEN** the direct assignment disappears and access evaluation continues to consider independent grants and the existing permission boundary

#### Scenario: Failed PostgreSQL audit

- **WHEN** recording the operator action fails
- **THEN** the direct assignment and its effective access retain their previous state
