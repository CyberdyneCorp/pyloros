## ADDED Requirements

### Requirement: Deliver account erasure to bound components
The service SHALL deliver committed account erasures to selected active deletion hooks when erasure dispatch is enabled.

#### Scenario: Account removed
- **WHEN** an administrator commits an erasure
- **THEN** each selected recipient receives only the event type and erased user ID, irrespective of its privacy settings, and execution history records that ID

#### Scenario: Outstanding deliveries
- **WHEN** the account is erased with older personal deliveries queued or completing
- **THEN** discard pending account deliveries and remove their execution history

#### Scenario: Erasure rolled back
- **WHEN** the transaction aborts
- **THEN** retain the account and its prior deliveries and enqueue no deletion event
