## ADDED Requirements

### Requirement: Rotate a webhook credential
Pyloros SHALL let a first-party administrator rotate a subscription's signing secret and return the newly generated secret in the rotation response.

#### Scenario: Replace a credential
- **WHEN** rotation succeeds
- **THEN** store the new secret encrypted and bound to the subscription identifier, retain the prior credential for a 24-hour overlap and audit the rotation without including either secret

### Requirement: Remove a webhook subscription
Pyloros SHALL allow a first-party administrator to remove a subscription and audit the removal.

#### Scenario: Retire a destination
- **WHEN** an administrator deletes an existing subscription
- **THEN** return HTTP 204, remove its delivery and attempt records, and retain the underlying emitted events
