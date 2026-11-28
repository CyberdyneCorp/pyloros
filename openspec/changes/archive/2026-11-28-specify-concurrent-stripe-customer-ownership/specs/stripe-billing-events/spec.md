## ADDED Requirements

### Requirement: Serialize first-time customer claims
When signed checkouts name the same unmapped customer and different accounts, only the first successfully committed claim SHALL establish ownership and grant access. A conflicting claim SHALL remain deferred with the reason `customer belongs to another user` on redelivery while that mapping exists.

#### Scenario: First claim commits
- **WHEN** two replicas process distinct, otherwise eligible checkouts for one customer
- **THEN** the first committed grant is handled, the conflicting event is acknowledged with handled false, and exactly one account receives access

#### Scenario: First claim rolls back
- **WHEN** the first checkout reaches commit and PostgreSQL rejects it while the other checkout is waiting
- **THEN** the first request returns HTTP 500 with no committed ledger entry and the waiting checkout may claim the customer
- **AND** redelivering the first event after the other claim commits records the conflict without changing ownership
