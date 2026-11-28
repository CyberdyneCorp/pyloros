## MODIFIED Requirements

### Requirement: Serialize first-time customer claims
When signed checkouts name the same unmapped customer and different accounts, the first committed mapping SHALL establish ownership. A checkout SHALL grant access only when its product is eligible. A conflicting claim SHALL remain deferred with the reason `customer belongs to another user` on redelivery while that mapping exists.

#### Scenario: First claim commits
- **WHEN** two replicas process distinct, otherwise eligible checkouts for one customer
- **THEN** the first committed grant is handled, the conflicting event is acknowledged with handled false, and exactly one account receives access

#### Scenario: First claim rolls back
- **WHEN** the first checkout reaches commit and PostgreSQL rejects it while the other checkout is waiting
- **THEN** the first request returns HTTP 500 with no committed ledger entry and the waiting checkout may claim the customer
- **AND** redelivering the first event after the other claim commits records the conflict without changing ownership

#### Scenario: Customer mapped while the catalog entry is unavailable
- **WHEN** a signed checkout supplies a product key and a valid account for a new customer, but the product is missing or inactive
- **THEN** commit the customer mapping and deferred event without granting access
- **AND** once the product is eligible, concurrent redeliveries of that event SHALL apply its grant once to the mapped account

#### Scenario: No product key supplied
- **WHEN** a checkout omits the product metadata required for a grant
- **THEN** defer it without establishing a customer mapping
- **AND** another eligible checkout may claim that customer while the original event remains deferred
