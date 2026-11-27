## ADDED Requirements

### Requirement: Deliver committed store entitlement changes
The service SHALL dispatch store grant and revocation events to the version selected for each active hook when delivery is enabled.

#### Scenario: Grant or revoke
- **WHEN** a store entitlement transition commits
- **THEN** run each selected component with the allowed event fields and persist its result in hook execution history

#### Scenario: Rollback or duplicate notification
- **WHEN** a billing transaction rolls back or a previously processed notification is replayed
- **THEN** produce no additional delivery

#### Scenario: Missing selection or worker outage
- **WHEN** a matching active hook has no selected version
- **THEN** leave the billing mutation retryable
- **WHEN** an execution worker becomes temporarily unavailable after commit
- **THEN** retain the delivery for retry with its original artifact version
